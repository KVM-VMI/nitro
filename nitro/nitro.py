#!/usr/bin/env python3


import os
import re
import logging
import subprocess
import libvirt
import time
import threading
from queue import Queue
from pebble import waitforqueues
from concurrent.futures import ThreadPoolExecutor, wait
from ctypes import *

from nitro.event import NitroEvent
from nitro.kvm import KVM, VM, VCPU

def find_qemu_pid(domain):
    logging.info('Finding QEMU pid for domain {}'.format(domain.name()))
    libvirt_vm_pid_file = '/var/run/libvirt/qemu/{}.pid'.format(domain.name())
    with open(libvirt_vm_pid_file, 'r') as f:
        content = f.read()
        pid = int(content)
        return pid

class Nitro:

    def __init__(self, domain):
        self.domain = domain
        self.pid = find_qemu_pid(domain)
        # init KVM
        self.kvm_io = KVM()
        # get VM fd
        vm_fd = self.kvm_io.attach_vm(self.pid)
        self.vm_io = VM(vm_fd)
        # get VCPU fds
        self.vcpus_io = self.vm_io.attach_vcpus()
        logging.info('Detected {} VCPUs'.format(len(self.vcpus_io)))

    def set_traps(self, enabled):
        self.domain.suspend()
        self.vm_io.set_syscall_trap(enabled)
        self.domain.resume()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.stop_listen()


    def listen(self):
        self.stop_request = threading.Event()
        pool = ThreadPoolExecutor(max_workers=len(self.vcpus_io))
        self.futures = []
        self.queue_list = []
        self.last_queue = None
        for vcpu_io in self.vcpus_io:
            # create queue for this vcpu
            q = Queue(maxsize=1)
            self.queue_list.append(q)
            # start to listen on this vcpu and report events in the queue
            f = pool.submit(self.listen_vcpu, vcpu_io, q)
            self.futures.append(f)

        # while a thread is still running
        while [f for f in self.futures if f.running()]:
            modified_queues = waitforqueues(self.queue_list)
            for q in modified_queues:
                event = q.get()
                self.last_queue = q
                yield event
                q.task_done()


    def listen_vcpu(self, vcpu_io, queue):
        logging.info('Start listening on VCPU {}'.format(vcpu_io.vcpu_nb))
        while not self.stop_request.is_set():
            nitro_raw_ev = vcpu_io.get_event()

            e = NitroEvent(nitro_raw_ev, vcpu_io.vcpu_nb)

            # put in the queue and wait for the event to be processed
            queue.put_nowait(e)
            queue.join()

            vcpu_io.continue_vm()

    def stop_listen(self):
        self.set_traps(False)
        self.stop_request.set()
        # ack last queue
        self.last_queue.task_done()
        # remove it from queue list
        self.queue_list.remove(self.last_queue)
        # wait for other queues to get an event
        while [q for q in self.queue_list if q.qsize() == 0]:
            time.sleep(1)
        # ack other queues
        [q.task_done() for q in self.queue_list]
        # wait for threads to exit
        wait(self.futures)

