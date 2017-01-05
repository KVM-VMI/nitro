#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py [options] <vm_name>

Options:
  -h --help     Show this screen.

"""

import os
import sys
import re
import logging
import subprocess
import json
import libvirt
from docopt import docopt
from queue import Queue
from pebble import waitforqueues
from concurrent.futures import ThreadPoolExecutor
from ctypes import *

from event import Event, Regs, SRegs, NitroEvent


class Nitro:

    def __init__(self, domain):
        self.domain = domain
        self.pid = self.find_qemu_pid(domain)
        self.libnitro = self.load_libnitro()
        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])
        logging.debug('Detected {} VCPUs'.format(self.nb_vcpu))

    def find_qemu_pid(self, domain):
        logging.debug('Finding QEMU pid for domain {}'.format(domain.name()))
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
        logging.debug('Setting traps to {}'.format(enabled))
        self.libnitro.set_syscall_trap(enabled)
        self.domain.resume()


    def __enter__(self):
        self.attach_vm()
        self.set_traps(True)
        return self

    def __exit__(self, type, value, traceback):
        self.set_traps(False)
        logging.debug('Closing KVM')
        self.libnitro.close_kvm()


    def listen(self):
        with ThreadPoolExecutor(max_workers=self.nb_vcpu) as pool:
            futures = []
            queue_list = []
            for vcpu_nb in range(self.nb_vcpu):
                # create queue for this vcpu
                q = Queue()
                queue_list.append(q)
                # start to listen on this vcpu and report events in the queue
                f = pool.submit(self.listen_vcpu, vcpu_nb, q)
                futures.append(f)

            # while a thread is still running
            while len([True for f in futures if f.running()]) > 0:
                modified_queues = waitforqueues(queue_list)
                for q in modified_queues:
                    event = q.get()
                    yield event
                    q.task_done()
            

    def listen_vcpu(self, vcpu_nb, queue):
        logging.debug('Start listening on VCPU {}'.format(vcpu_nb))
        while True:
            try:
                nitro_ev = NitroEvent()
                self.libnitro.get_event(vcpu_nb, byref(nitro_ev))
                regs = Regs()
                sregs = SRegs()
                self.libnitro.get_regs(vcpu_nb, byref(regs))
                self.libnitro.get_sregs(vcpu_nb, byref(sregs))

                e = Event(nitro_ev, regs, sregs, vcpu_nb)

                # put in the queue and wait for the event to be treated
                queue.put_nowait(e)
                queue.join()

                self.libnitro.continue_vm(vcpu_nb)
            except KeyboardInterrupt:
                logging.debug('Interrupt thread')
                break

def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    vm_name = args['<vm_name>']
    con = libvirt.open('qemu:///system')
    domain = con.lookupByName(vm_name)

    with Nitro(domain) as nitro:
        for event in nitro.listen():
            logging.debug(event)

if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
