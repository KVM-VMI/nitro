#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py <vm_name>

Options:
  -h --help     Show this screen.

"""


import os
import sys
import re
import struct
import logging
import subprocess
import json
from pprint import pprint
from ctypes import *

from docopt import docopt
import libvirt

from event import Event, Regs, SRegs
from backend import Backend


class Nitro:

    def __init__(self, pid):
        self.pid = pid
        logging.debug('Loading libnitro.so')
        self.libnitro = cdll.LoadLibrary('./libnitro/libnitro.so')


    def __enter__(self):
        logging.debug('Initializing KVM')
        self.libnitro.init_kvm()
        logging.debug('Attaching to the VM')
        self.libnitro.attach_vm(c_int(self.pid))
        logging.debug('Attaching to VCPUs')
        self.libnitro.attach_vcpus()
        logging.debug('Setting Traps')
        self.libnitro.set_syscall_trap(True)
        return self

    def __exit__(self, type, value, traceback):
        logging.debug('Unsetting Traps')
        self.libnitro.set_syscall_trap(False)
        logging.debug('Closing KVM')
        self.libnitro.close_kvm()


    def listen(self):
        while 1:
            try:
                event = self.libnitro.get_event(0)
                regs = Regs()
                sregs = SRegs()
                self.libnitro.get_regs(0, byref(regs))
                self.libnitro.get_sregs(0, byref(sregs))

                e = Event(event, regs, sregs)

                yield(e)
                self.libnitro.continue_vm(0)
            except KeyboardInterrupt:
                break

def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    vm_name = args['<vm_name>']
    logging.debug('Finding PID of VM {}'.format(vm_name))
    output = subprocess.getoutput("pgrep -f -o 'qemu.*-name {}'".format(vm_name))
    pid = int(output)
    logging.debug('pid = {}'.format(pid))

    backend = Backend(vm_name)
    with Nitro(pid) as nitro:
        for event in nitro.listen():
            backend.new_event(event)

if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
