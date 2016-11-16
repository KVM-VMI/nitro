#!/usr/bin/env python

"""Nitro.

Usage:
  nitro.py [options] <vm_name> (32 | 64)

Options:
  -h --help     Show this screen.
  --nobackend   Dont analyze events

"""


import os
import sys
import re
import struct
import logging
import subprocess
import commands
import json
from pprint import pprint
from ctypes import *

from docopt import docopt
import libvirt

from event import Event, Regs, SRegs, NitroEvent
from backend import Backend


class Nitro:

    def __init__(self, pid, vm_name):
        self.pid = pid
        logging.debug('Loading libnitro.so')
        self.libnitro = cdll.LoadLibrary('./libnitro/libnitro.so')
        con = libvirt.open('qemu:///system')
        self.domain = con.lookupByName(vm_name)


    def __enter__(self):
        logging.debug('Suspending the Guest')
        self.domain.suspend()
        logging.debug('Initializing KVM')
        self.libnitro.init_kvm()
        logging.debug('Attaching to the VM')
        self.libnitro.attach_vm(c_int(self.pid))
        logging.debug('Attaching to VCPUs')
        self.libnitro.attach_vcpus()
        logging.debug('Setting Traps')
        self.libnitro.set_syscall_trap(True)
        logging.debug('Resuming the Guest')
        self.domain.resume()
        return self

    def __exit__(self, type, value, traceback):
        logging.debug('Suspending the Guest')
        self.domain.suspend()
        logging.debug('Unsetting Traps')
        self.libnitro.set_syscall_trap(False)
        logging.debug('Closing KVM')
        self.libnitro.close_kvm()
        logging.debug('Resuming the Guest')
        self.domain.resume()


    def listen(self):
        while 1:
            try:
                nitro_ev = NitroEvent()
                self.libnitro.get_event(0, byref(nitro_ev))
                regs = Regs()
                sregs = SRegs()
                self.libnitro.get_regs(0, byref(regs))
                self.libnitro.get_sregs(0, byref(sregs))

                e = Event(nitro_ev, regs, sregs)

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
    if args['32']:
        arch = 32
    else:
        arch = 64
    logging.debug('Finding PID of VM {}'.format(vm_name))
    output = commands.getoutput("pgrep -f -o 'qemu.*-name {}'".format(vm_name))
    pid = int(output)
    logging.debug('pid = {}'.format(pid))

    if not args['--nobackend']:
        backend = Backend(vm_name, arch)
    with Nitro(pid, vm_name) as nitro:
        for event in nitro.listen():
            if not args['--nobackend']:
                backend.new_event(event)
            else:
                logging.debug(event.display())

if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
