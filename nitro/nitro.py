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

from nitro.event import NitroEvent, Regs, SRegs, NitroEventStr

class Nitro:

    def __init__(self, domain):
        self.domain = domain
        self.pid = self.find_qemu_pid(domain)
        self.libnitro = self.load_libnitro()
        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])
        logging.info('Detected {} VCPUs'.format(self.nb_vcpu))

    def find_qemu_pid(self, domain):
        logging.info('Finding QEMU pid for domain {}'.format(domain.name()))
        libvirt_vm_pid_file = '/var/run/libvirt/qemu/{}.pid'.format(domain.name())
        with open(libvirt_vm_pid_file, 'r') as f:
            content = f.read()
            pid = int(content)
            return pid

    def load_libnitro(self):
        logging.debug('Loading libnitro.so')
        script_dir = os.path.dirname(os.path.realpath(__file__))
        libnitro_so_path = os.path.join(script_dir, 'libnitro', 'libnitro.so')
        libnitro = cdll.LoadLibrary(libnitro_so_path)
        return libnitro

    def attach_vm(self):
        logging.debug('Initializing KVM')
        self.libnitro.init_kvm()
        logging.debug('Attaching to the VM')
        self.libnitro.attach_vm(c_int(self.pid))
        logging.debug('Attaching to VCPUs')
        self.libnitro.attach_vcpus()


    def set_traps(self, enabled):
        self.domain.suspend()
        logging.info('Setting traps to {}'.format(enabled))
        self.libnitro.set_syscall_trap(enabled)
        self.domain.resume()


    def __enter__(self):
        self.attach_vm()
        return self

    def __exit__(self, type, value, traceback):
        self.stop_listen()
        logging.debug('Closing KVM')
        self.libnitro.close_kvm()


    def listen(self):
        self.set_traps(True)
        self.stop_request = threading.Event()
        pool = ThreadPoolExecutor(max_workers=self.nb_vcpu)
        self.futures = []
        self.queue_list = []
        for vcpu_nb in range(self.nb_vcpu):
            # create queue for this vcpu
            q = Queue(maxsize=1)
            self.queue_list.append(q)
            # start to listen on this vcpu and report events in the queue
            f = pool.submit(self.listen_vcpu, vcpu_nb, q)
            self.futures.append(f)

        # while a thread is still running
        while [f for f in self.futures if f.running()]:
            modified_queues = waitforqueues(self.queue_list)
            for q in modified_queues:
                event = q.get()
                self.last_queue = q
                yield event
                q.task_done()


    def listen_vcpu(self, vcpu_nb, queue):
        logging.info('Start listening on VCPU {}'.format(vcpu_nb))
        while not self.stop_request.is_set():
            nitro_ev = NitroEventStr()
            self.libnitro.get_event(vcpu_nb, byref(nitro_ev))

            regs = Regs()
            sregs = SRegs()
            self.libnitro.get_regs(vcpu_nb, byref(regs))
            self.libnitro.get_sregs(vcpu_nb, byref(sregs))

            e = NitroEvent(nitro_ev, regs, sregs, vcpu_nb)

            # put in the queue and wait for the event to be treated
            queue.put_nowait(e)
            queue.join()

            self.libnitro.continue_vm(vcpu_nb)

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

