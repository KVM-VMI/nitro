#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py [options] <vm_name>

Options:
  -h --help     Show this screen.

"""

import logging
import signal
import json
import libvirt
from docopt import docopt

from libnitro import Nitro
from backend import Backend

run = True
# def new signal for SIGINT
def sigint_handler(signal, frame):
    global run
    run = False
signal.signal(signal.SIGINT, sigint_handler)


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    vm_name = args['<vm_name>']
    # get domain from libvirt
    con = libvirt.open('qemu:///system')
    domain = con.lookupByName(vm_name)

    counter = 0
    events = []
    # start Nitro
    with Nitro(domain) as nitro:
        backend = Backend(domain)
        for event in nitro.listen():
            syscall = backend.process_event(event)
            events.append(syscall.info())
            # wait for CTRL+C to stop
            if not run:
                break
    logging.info('Writing events')
    with open('events.json', 'w') as f:
        json.dump(events, f)



if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
