#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py [options] <vm_name>

Options:
  -h --help     Show this screen.
  --nobackend   Don't analyze events
  --stdout      Display events on stdout, not in a log file

"""

import logging
import signal
import json
import libvirt
from pprint import pprint
from docopt import docopt

from nitro.nitro import Nitro
from nitro.libvmi import LibvmiError


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


def callback(syscall, backend):
    pass

class NitroRunner:

    def __init__(self, vm_name, analyze_enabled, stdout):
        self.vm_name = vm_name
        self.analyze_enabled = analyze_enabled
        self.stdout = stdout
        # get domain from libvirt
        con = libvirt.open('qemu:///system')
        self.domain = con.lookupByName(vm_name)
        self.events = []
        # define new SIGINT handler, to stop nitro
        signal.signal(signal.SIGINT, self.sigint_handler)

    def run(self):
        self.nitro = Nitro(self.domain, self.analyze_enabled)
        if self.analyze_enabled:
            # defining hooks
            self.nitro.backend.define_hook('NtOpenFile', callback)
            self.nitro.backend.define_hook('NtCreateFile', callback)
            self.nitro.backend.define_hook('NtClose', callback)

        self.nitro.listener.set_traps(True)
        for event in self.nitro.listen():
            event_info = event.as_dict()
            if self.analyze_enabled:
                try:
                    syscall = self.nitro.backend.process_event(event)
                except LibvmiError:
                    logging.error("Backend event processing failure")
                else:
                    event_info = syscall.as_dict()
            if self.stdout:
                pprint(event_info, width=1)
            else:
                self.events.append(event_info)

        if self.events:
            logging.info('Writing events')
            with open('events.json', 'w') as f:
                json.dump(self.events, f, indent=4)

    def sigint_handler(self, signal, frame):
        logging.info('CTRL+C received, stopping Nitro')
        self.nitro.stop()


def main(args):
    vm_name = args['<vm_name>']
    analyze_enabled = False if args['--nobackend'] else True
    stdout = args['--stdout']
    runner = NitroRunner(vm_name, analyze_enabled, stdout)
    runner.run()


if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
