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
        self.domain = domain
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

    def stop(self):
        self.stop_listen()
        self.kvm_io.close()

    def listen(self):
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
                # remember last continue_event for stop_listen()
                self.current_cont_event = continue_event
                yield event
                continue_event.set()

        # raise listen_vcpu exceptions if any
        for f in self.futures:
            if f.exception() is not None:
                raise f.exception()
        logging.info('Stop Nitro listening')

    def listen_vcpu(self, vcpu_io, queue):
        logging.info('Start listening on VCPU %s', vcpu_io.vcpu_nb)
        # we need a per thread continue event
        continue_event = threading.Event()
        while not self.stop_request.is_set():
            try:
                nitro_raw_ev = vcpu_io.get_event()
            except ValueError as e:
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

    def stop_listen(self):
        self.set_traps(False)
        self.stop_request.set()
        nb_threads = len([f for f in self.futures if f.running()])
        if nb_threads:
            # ack current thread
            self.current_cont_event.set()
            # wait for current thread to terminate
            while [f for f in self.futures if f.running()] == nb_threads:
                time.sleep(0.1)
            # ack the rest of the threads
            while [f for f in self.futures if f.running()]:
                if self.queue.full():
                    (*rest, continue_event) = self.queue.get()
                    continue_event.set()
                # let the threads terminate
                time.sleep(0.1)
            # wait for threads to exit
            wait(self.futures)

    def add_syscall_filter(self, syscall_nb):
        self.vm_io.add_syscall_filter(syscall_nb)

    def remove_syscall_filter(self, syscall_nb):
        self.vm_io.remove_syscall_filter(syscall_nb)
