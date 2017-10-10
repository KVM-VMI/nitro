#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py [options] <vm_name>

Options:
  -h --help            Show this screen
  --nobackend          Don't analyze events
  -o FILE --out=FILE   Output file (stdout if not specified)

"""

import logging
import signal
import json
from pprint import pprint

import libvirt
from docopt import docopt

from nitro.nitro import Nitro
from nitro.libvmi import LibvmiError


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


class NitroRunner:

    def __init__(self, vm_name, analyze_enabled, output=None):
        self.vm_name = vm_name
        self.analyze_enabled = analyze_enabled
        self.output = output
        # get domain from libvirt
        con = libvirt.open('qemu:///system')
        self.domain = con.lookupByName(vm_name)
        self.events = []
        self.nitro = None
        # define new SIGINT handler, to stop nitro
        signal.signal(signal.SIGINT, self.sigint_handler)

    def run(self):
        self.nitro = Nitro(self.domain, self.analyze_enabled)
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
            if self.output is None:
                pprint(event_info, width=1)
            else:
                self.events.append(event_info)

        if self.output is not None:
            logging.info('Writing events')
            with open(self.output, 'w') as f:
                json.dump(self.events, f, indent=4)

    def sigint_handler(self, *args, **kwargs):
        logging.info('CTRL+C received, stopping Nitro')
        self.nitro.stop()


def main(args):
    vm_name = args['<vm_name>']
    analyze_enabled = False if args['--nobackend'] else True
    output = args['--out']
    runner = NitroRunner(vm_name, analyze_enabled, output)
    runner.run()


if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
