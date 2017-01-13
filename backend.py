import logging
import re
import os
import libvirt
import subprocess
import shutil
import json
import zmq
import base64
from tempfile import NamedTemporaryFile
from event import SyscallDirection

GETSYMBOLS_SCRIPT = 'symbols.py'
LIBVMI_HELPER = 'libvmi_helper.py'
NITRO_LIBVMI_SOCKET = '/tmp/nitro_libvmi.sock'

class Process:

    def __init__(self, cr3, start_eproc, name, pid):
        self.cr3 = cr3
        self.start_eproc = start_eproc
        self.name = name
        self.pid = pid

    def info(self):
        info = {}
        info['name'] = self.name
        info['pid'] = self.pid
        return info

class Syscall:

    def __init__(self, event, name, process):
        self.event = event
        self.name = name
        self.process = process

    def info(self):
        info = {}
        info['name'] = self.name
        info['event'] = self.event.info()
        info['process'] = self.process.info()
        return info


class Backend:

    def __init__(self, domain):
        self.domain = domain
        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])
        # create on syscall stack per vcpu
        self.syscall_stack = {}
        for vcpu_nb in range(self.nb_vcpu):
            self.syscall_stack[vcpu_nb] = []
        self.load_symbols()
        # run libvmi helper subprocess
        self.run_libvmi_helper()
        self.processes = {}

    def load_symbols(self):
        with NamedTemporaryFile() as ram_dump:
            # take a ram dump
            logging.debug('Dumping physical memory to {}'.format(ram_dump.name))
            flags = libvirt.VIR_DUMP_MEMORY_ONLY
            dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
            self.domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
            # build symbols.py absolute path
            script_dir = os.path.dirname(os.path.realpath(__file__))
            symbols_script_path = os.path.join(script_dir, GETSYMBOLS_SCRIPT)
            # call rekall on ram dump
            logging.debug('Extracting symbols with Rekall')
            python2 = shutil.which('python2')
            symbols_process = [python2, symbols_script_path, ram_dump.name]
            output = subprocess.check_output(symbols_process)
        logging.debug('Loading symbols')
        # load output as json
        jdata = json.loads(output.decode('utf-8'))
        # load ssdt entries
        nt_ssdt = {'ServiceTable' : {}, 'ArgumentTable' : {}}
        win32k_ssdt = {'ServiceTable' : {}, 'ArgumentTable' : {}}
        self.sdt = [nt_ssdt, win32k_ssdt]
        cur_ssdt = None
        for e in jdata:
            if isinstance(e, list) and e[0] == 'r':
                if e[1]["divider"] is not None:
                    # new table
                    m = re.match(r'Table ([0-9]) @ .*', e[1]["divider"])
                    idx = int(m.group(1))
                    cur_ssdt = self.sdt[idx]['ServiceTable']
                else:
                    entry = e[1]["entry"]
                    full_name = e[1]["symbol"]["symbol"]
                    # add entry  to our current ssdt
                    cur_ssdt[entry] = full_name
                    logging.debug('Add SSDT entry [{}] -> {}'.format(entry, full_name))
        # last json entry is kernel symbols
        self.kernel_symbols = jdata[-1]

    def run_libvmi_helper(self):
        # build path to libvmi
        script_dir = os.path.dirname(os.path.realpath(__file__))
        libvmi_helper_path = os.path.join(script_dir, LIBVMI_HELPER)
        args = [libvmi_helper_path, self.domain.name()]
        logging.debug('Starting libvmi helper')
        self.libvmi_proc = subprocess.Popen(args)
        # init zmq
        self.ctxt = zmq.Context()
        self.socket = self.ctxt.socket(zmq.PAIR)
        self.socket.connect('ipc://{}'.format(NITRO_LIBVMI_SOCKET))
        logging.debug('Connected to libvmi helper')

    def process_event(self, event):
        cr3 = event.sregs.cr3
        process = self.associate_process(cr3)
        if event.direction == SyscallDirection.exit:
            try:
                syscall_name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                syscall_name = 'Unknown'
        else:
            syscall_name = self.get_syscall_name(event.regs.rax)
            # push them to the stack
            self.syscall_stack[event.vcpu_nb].append(syscall_name)
        syscall = Syscall(event, syscall_name, process)
        return syscall

    def associate_process(self, cr3):
        p = None
        try:
            p = self.processes[cr3]
        except KeyError:
            p = self.find_eprocess(cr3)
            self.processes[cr3] = p
        return p

    def find_eprocess(self, cr3):
        # read PsActiveProcessHead list_entry
        flink = self.read_addr_ksym('PsActiveProcessHead')
        
        while flink != self.kernel_symbols['PsActiveProcessHead']:
            # get start of EProcess
            start_eproc = flink - self.kernel_symbols['ActiveProcessLinks_off']
            # move to start of DirectoryTableBase
            directory_table_base_off = start_eproc + self.kernel_symbols['DirectoryTableBase_off']
            # read directory_table_base
            directory_table_base = self.read_addr_va(directory_table_base_off, 0)
            # compare to our cr3
            if cr3 == directory_table_base:
                # get name
                image_file_name_off = start_eproc + self.kernel_symbols['ImageFileName_off']
                content = self.read_va(image_file_name_off, 0, 15)
                image_file_name = content.rstrip(b'\0').decode('utf-8')
                # get pid
                unique_processid_off = start_eproc + self.kernel_symbols['UniqueProcessId_off']
                pid = self.read_addr_va(unique_processid_off, 0)
                eprocess = Process(cr3, start_eproc, image_file_name, pid)
                return eprocess

            # read new flink
            flink = self.read_addr_va(flink, 0)


    def get_syscall_name(self, rax):
        ssn = rax & 0xFFF
        idx = (rax & 0x3000) >> 12
        try:
            syscall_name = self.sdt[idx]['ServiceTable'][ssn]
        except (KeyError, IndexError):
            syscall_name = 'Table{}!Unknown'.format(idx)
        return syscall_name

    def read_addr_va(self, address, pid=0):
        msg = {}
        msg['function'] = 'read_addr_va'
        args = {}
        args['address'] = address
        args['pid'] = pid
        msg['args'] = args
        self.socket.send_json(msg)
        reply = self.socket.recv_json()
        value = int(reply['result'])
        return value

    def read_va(self, address, pid, size):
        msg = {}
        msg['function'] = 'read_va'
        args = {}
        args['address'] = address
        args['pid'] = pid
        args['size'] = size
        msg['args'] = args
        self.socket.send_json(msg)
        reply = self.socket.recv_json()
        value = base64.b64decode(reply['result'])
        return value

    def read_addr_ksym(self, symbol):
        msg = {}
        msg['function'] = 'read_addr_ksym'
        args = {}
        args['symbol'] = symbol
        msg['args'] = args
        self.socket.send_json(msg)
        reply = self.socket.recv_json()
        addr = int(reply['result'])
        return addr
