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
from nitro.backend import Backend

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

    if args['--nobackend']:
        with Nitro(domain) as nitro:
            nitro.set_traps(True)
            for event in nitro.listen():
                ev_info = event.info()

                if args['--stdout']:
                    pprint(ev_info, width=1)
                else:
                    events.append(ev_info)

                # stop properly by CTRL+C
                if not run:
                    break
    else:
        with Backend(domain) as backend:
            backend.nitro.set_traps(True)
            for event in backend.nitro.listen():
                syscall = backend.process_event(event)
                ev_info = syscall.info()

                if args['--stdout']:
                    pprint(ev_info, width=1)
                else:
                    events.append(ev_info)

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
