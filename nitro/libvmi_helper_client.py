import logging
import os
import shutil
import zmq
import subprocess
import base64
from docopt import docopt

NITRO_LIBVMI_SOCKET = '/tmp/nitro_libvmi.sock'
LIBVMI_HELPER = 'libvmi_helper.py'

class LibvmiHelperClient:

    METHOD_RETURN_TYPE = {
            'read_addr_va': int,
            'read_va': bytes,
            'read_addr_ksym': int,
            'translate_ksym2v': int,
            'get_offset': int,
            'get_winver_str': str,
            'init_pyvmi_name': str,
            'init_pyvmi_config': str,
        }

    def __init__(self, domain, vmi_config=None):
        self.domain = domain
        # build path to libvmi
        script_dir = os.path.dirname(os.path.realpath(__file__))
        libvmi_helper_path = os.path.join(script_dir, LIBVMI_HELPER)
        python2 = shutil.which('python2')
        args = [python2, libvmi_helper_path, self.domain.name()]
        logging.debug('Starting libvmi helper {}'.format(args))
        # run subprocess
        self.libvmi_proc = subprocess.Popen(args)
        # init zmq
        self.ctxt = zmq.Context()
        self.socket = self.ctxt.socket(zmq.PAIR)
        self.socket.connect('ipc://{}'.format(NITRO_LIBVMI_SOCKET))
        # init
        if vmi_config:
            self.init_pyvmi_config(vmi_config)
        else:
            self.init_pyvmi_name(domain.name())
        # sending test request
        vers = self.get_winver_str()
        logging.debug('Windows version : {}'.format(vers))

    def get_winver_str(self, *args):
        return self.call_helper('get_winver_str', *args)

    def read_addr_va(self, *args):
        return self.call_helper('read_addr_va', *args)

    def read_va(self, *args):
        return self.call_helper('read_va', *args)

    def read_addr_ksym(self, *args):
        return self.call_helper('read_addr_ksym', *args)

    def translate_ksym2v(self, *args):
        return self.call_helper('translate_ksym2v', *args)

    def get_offset(self, *args):
        return self.call_helper('get_offset', *args)

    def init_pyvmi_name(self, *args):
        return self.call_helper('init_pyvmi_name', *args)

    def init_pyvmi_config(self, *args):
        return self.call_helper('init_pyvmi_config', *args)


    def call_helper(self, func_name, *args):
        # prepare request
        request = {}
        request['function'] = func_name
        request['args'] = args
        # send it
        logging.debug('sending request {}'.format(request))
        self.socket.send_json(request)
        reply = self.socket.recv_json()
        # decode base64 reply
        result = base64.b64decode(reply['result'])
        # convert type
        return_type = self.METHOD_RETURN_TYPE[func_name]
        result = return_type(result)
        return result

    def stop(self, *args):
        # ask subprocess to stop
        request = {}
        request['function'] = 'stop'
        logging.debug('sending stop command')
        self.socket.send_json(request)
        logging.debug('waiting for subprocess')
        # wait for subprocess
        self.libvmi_proc.wait(timeout=10)

