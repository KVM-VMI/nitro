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
import subprocess
import base64
from docopt import docopt

NITRO_LIBVMI_SOCKET = '/tmp/nitro_libvmi.sock'

class LibvmiHelper:

    METHOD_ARGS_TYPE = {
            'read_addr_va': {'address': long, 'pid': int},
            'read_va': {'address': long, 'pid': int, 'size': int},
            'read_addr_ksym': {'symbol': str},
            'translate_ksym2v': {'symbol': str},
            'get_winver_str': {},
            }

    def __init__(self, vm_name):
        self.vmi = pyvmi.init(vm_name, 'complete')
        self.ctxt = zmq.Context()
        self.socket = self.ctxt.socket(zmq.PAIR)
        self.socket.bind('ipc://{}'.format(NITRO_LIBVMI_SOCKET))

    def listen(self):
        while True:
            request = self.socket.recv_json()
            logging.debug('New request {}'.format(request))
            func_name = request['function']
            if func_name == 'stop':
                break

            # build args with correct type
            typed_args = []
            for k,v in self.METHOD_ARGS_TYPE[func_name].iteritems():
                cur_arg = request['args'].pop(0)
                typed_args.append(v(cur_arg))
            # call libvmi
            libvmi_func = getattr(self.vmi, func_name)
            result = libvmi_func(*typed_args)
            logging.debug('result: {}'.format(result))
            # encode result b64 (may be bytes)
            result = base64.b64encode(str(result))
            # return response
            response = {'result': result}
            logging.debug('sending response: {}'.format(response))
            self.socket.send_json(response)


def init_logger():
    logging.basicConfig(filename='libvmi_helper.log', level=logging.DEBUG, format='%(message)s')

def main(args):
    vm_name = args['<vm_name>']
    helper = LibvmiHelper(vm_name)
    helper.listen()


if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
