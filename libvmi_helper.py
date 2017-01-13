#!/usr/bin/env python2

"""Libvmi Helper.

Usage:
  libvmi_helper.py [options] <vm_name>

Options:
  -h --help     Show this screen.

"""

import logging
import pyvmi
import zmq
import base64
from docopt import docopt

SOCKET_PATH = '/tmp/nitro_libvmi.sock'

class LibvmiHelper:

    def __init__(self, vm_name):
        self.vmi = pyvmi.init(vm_name, 'complete')
        self.ctxt = zmq.Context()
        self.socket = self.ctxt.socket(zmq.PAIR)
        self.socket.bind('ipc://{}'.format(SOCKET_PATH))

    def listen(self):
        while True:
            msg = self.socket.recv_json()
            func_name = msg['function']
            func = getattr(self, func_name)
            result = func(msg['args'])
            reply = {}
            reply['result'] = result
            self.socket.send_json(reply)


    def read_addr_va(self, args):
        logging.debug('read_addr_va')
        address = int(args['address'])
        pid = int(args['pid'])
        result = self.vmi.read_addr_va(address, pid)
        return result

    def read_va(self, args):
        logging.debug('read_va')
        address = int(args['address'])
        pid = int(args['pid'])
        size = int(args['size'])
        result = self.vmi.read_va(address, pid, size)
        return base64.b64encode(result)

    def read_addr_ksym(self, args):
        logging.debug('read_addr_ksym')
        symbol = args['symbol']
        result = self.vmi.read_addr_ksym(symbol)
        return result


def init_logger():
    logging.basicConfig(filename='libvmi_helper.log', level=logging.DEBUG, format='%(message)s')

def main(args):
    vm_name = args['<vm_name>']
    helper = LibvmiHelper(vm_name)
    helper.listen()


if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
