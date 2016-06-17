#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py <pid>

Options:
  -h --help     Show this screen.

"""


import os
import sys
import logging
from ctypes import *

from docopt import docopt

KVM_NITRO_EVENT_ERROR = 1
KVM_NITRO_EVENT_SYSCALL = 2
KVM_NITRO_EVENT_SYSRET = 3

def main(args):
    logging.basicConfig(level=logging.DEBUG)
    pid = int(args['<pid>'])
    logging.debug('pid = {}'.format(pid))
    logging.debug('Loading libnitro.so')
    libnitro = cdll.LoadLibrary('./libnitro/libnitro.so')
    logging.debug('Initializing KVM')
    fd = libnitro.init_kvm()
    logging.debug('Attaching to the VM')
    vmfd = libnitro.attach_vm(c_int(pid))
    logging.debug('Attaching to VCPUs')
    nb_vcpus = libnitro.attach_vcpus()
    logging.debug('Setting Traps')
    libnitro.set_syscall_trap(True)
    while 1:
        try:
            event = libnitro.get_event(0)
            if event == KVM_NITRO_EVENT_SYSCALL:
                logging.debug('SYSCALL')
            elif event == KVM_NITRO_EVENT_SYSRET:
                logging.debug('SYSRET')

            libnitro.continue_vm(0)
        except KeyboardInterrupt:
            logging.debug('Unsetting Traps')
            libnitro.set_syscall_trap(False)
            logging.debug('Closing KVM')
            libnitro.close_kvm()
            break

if __name__ == '__main__':
    main(docopt(__doc__))
