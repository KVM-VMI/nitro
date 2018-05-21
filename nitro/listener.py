#!/usr/bin/env python3

import re
import psutil
import logging
import time
import threading
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, wait

from nitro.event import NitroEvent
from nitro.kvm import KVM, VM

class QEMUNotFoundError(Exception):
    pass

def find_qemu_pid(vm_name):
    """
    Find QEMU's PID that is associated with a given virtual machine
    
    :param str vm_name: libvirt domain name
    :rtype: int
    """
    logging.info('Finding QEMU pid for domain %s', vm_name)
    libvirt_vm_pid_file = '/var/run/libvirt/qemu/{}.pid'.format(vm_name)
    try:
        with open(libvirt_vm_pid_file, 'r') as f:
            content = f.read()
            pid = int(content)
            return pid
    except IOError:
        for proc in psutil.process_iter():
            cmdline = proc.cmdline()[1:]
            if proc.name() == "qemu-system-x86_64" and \
               next((True for k, v in zip(cmdline, cmdline[1:]) if k == "-name" and vm_name in v), False):
                return proc.pid
        logging.critical('Cannot find QEMU')
        raise QEMUNotFoundError('Cannot find QEMU')

class Listener:
    """
    Class for listening to events from a virtual machine.
    """

    __slots__ = (
        'domain',
        'pid',
        'kvm_io',
        'vm_io',
        'vcpus_io',
        'stop_request',
        'futures',
        'queue',
        'current_cont_event',
    )

    def __init__(self, domain):
        #: Libvirt domain that the Listener is monitoring
        self.domain = domain
        #: Pid of the QEMU instance that is being monitored
        self.pid = find_qemu_pid(domain.name())
        # init KVM
        self.kvm_io = KVM()
        # get VM fd
        vm_fd = self.kvm_io.attach_vm(self.pid)
        self.vm_io = VM(vm_fd)
        # get VCPU fds
        self.vcpus_io = self.vm_io.attach_vcpus()
        logging.info('Detected %s VCPUs', len(self.vcpus_io))
        self.stop_request = None
        self.futures = None
        self.queue = None
        self.current_cont_event = None

    def set_traps(self, enabled):
        if self.domain.isActive():
            self.domain.suspend()
            self.vm_io.set_syscall_trap(enabled)
            self.domain.resume()

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()

    def stop(self, synchronous=True):
        """Stop listening for system calls"""
        self.set_traps(False)
        self.stop_request.set()
        if synchronous:
            # wait for threads to exit
            wait(self.futures)
        self.kvm_io.close()

    def listen(self):
        """Generator yielding NitroEvents from the virtual machine"""
        self.stop_request = threading.Event()
        pool = ThreadPoolExecutor(max_workers=len(self.vcpus_io))
        self.futures = []
        self.queue = Queue(maxsize=1)
        self.current_cont_event = None
        for vcpu_io in self.vcpus_io:
            # start to listen on this vcpu and report events in the queue
            f = pool.submit(self.listen_vcpu, vcpu_io, self.queue)
            self.futures.append(f)

        # while a thread is still running
        while [f for f in self.futures if f.running()]:
            try:
                (event, continue_event) = self.queue.get(timeout=1)
            except Empty:
                # domain has crashed or is shutdown ?
                if not self.domain.isActive():
                    self.stop_request.set()
            else:
                if not self.stop_request.is_set():
                    yield event
                continue_event.set()

        # raise listen_vcpu exceptions if any
        for f in self.futures:
            if f.exception() is not None:
                raise f.exception()
        logging.info('Stop Nitro listening')

    def listen_vcpu(self, vcpu_io, queue):
        """Listen to an individual virtual CPU"""
        logging.info('Start listening on VCPU %s', vcpu_io.vcpu_nb)
        # we need a per thread continue event
        continue_event = threading.Event()
        while not self.stop_request.is_set():
            try:
                nitro_raw_ev = vcpu_io.get_event()
            except ValueError as e:
                if not self.vm_io.syscall_filters:
                    # if there are no filters, get_event should not timeout
                    # since we capture all system calls
                    # so log the error
                    logging.debug(str(e))
            else:
                e = NitroEvent(nitro_raw_ev, vcpu_io)
                # put the event in the queue
                # and wait for the event to be processed,
                # when the main thread will set the continue_event
                item = (e, continue_event)
                queue.put(item)
                continue_event.wait()
                # reset continue_event
                continue_event.clear()
                vcpu_io.continue_vm()

        logging.debug('stop listening on VCPU %s', vcpu_io.vcpu_nb)

    def add_syscall_filter(self, syscall_nb):
        """Add system call filter to a virtual machine"""
        self.vm_io.add_syscall_filter(syscall_nb)

    def remove_syscall_filter(self, syscall_nb):
        """Remove system call filter form a virtual machine"""
        self.vm_io.remove_syscall_filter(syscall_nb)
