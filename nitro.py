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
                if event == KVM_NITRO_EVENT_SYSCALL:
                    logging.debug('SYSCALL')
                elif event == KVM_NITRO_EVENT_SYSRET:
                    logging.debug('SYSRET')

                yield(event)
                self.libnitro.continue_vm(0)
            except KeyboardInterrupt:
                break

def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    pid = int(args['<pid>'])
    logging.debug('pid = {}'.format(pid))

    with Nitro(pid) as nitro:
        for event in nitro.listen():
            logging.debug(event)

if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
