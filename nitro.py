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
import time
from pprint import pprint
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
    logger.setLevel(logging.INFO)

def main(args):
    vm_name = args['<vm_name>']
    # get domain from libvirt
    con = libvirt.open('qemu:///system')
    domain = con.lookupByName(vm_name)

    events = []
    # start Nitro
    with Nitro(domain) as nitro:
        with Backend(domain) as backend:
            for event in nitro.listen():
                syscall = backend.process_event(event)
                sys_info = syscall.info()
                events.append(sys_info)
                
                # stop properly by CTRL+C
                if not run:
                    break
    logging.info('Writing events')
    with open('events.json', 'w') as f:
        json.dump(events, f)



if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
