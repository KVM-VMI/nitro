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
import time
from pprint import pprint
from docopt import docopt

from nitro.nitro import Nitro
from nitro.backends import get_backend

run = True

# def new signal for SIGINT
def sigint_handler(signal, frame):
    global run
    run = False
signal.signal(signal.SIGINT, sigint_handler)


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


def main(args):
    vm_name = args['<vm_name>']
    # get domain from libvirt
    con = libvirt.open('qemu:///system')
    domain = con.lookupByName(vm_name)

    events = []
    # init backend if necessary
    analyze_enabled = not args['--nobackend']
    backend = get_backend(domain, analyze_enabled)
    if backend is None:
        logging.critical("Failed to select backend")

    with backend:
        backend.nitro.set_traps(True)
        for event in backend.nitro.listen():
            event_info = event.as_dict()
            if analyze_enabled:
                syscall = backend.process_event(event)
                event_info = syscall.as_dict()

            if args['--stdout']:
                pprint(event_info, width=1)
            else:
                events.append(event_info)

            # stop properly by CTRL+C
            if not run:
                break

    if events:
        logging.info('Writing events')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)


if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
