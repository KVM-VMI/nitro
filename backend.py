import logging
import re
import os
import libvirt
import subprocess
import shutil
import json
from tempfile import NamedTemporaryFile
from event import SyscallDirection

GETSYMBOLS_SCRIPT = 'symbols.py'

class Syscall:

    def __init__(self, event, name):
        self.event = event
        self.name = name

    def info(self):
        info = {}
        info['name'] = self.name
        info['event'] = self.event.info()
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

    def process_event(self, event):
        if event.direction == SyscallDirection.exit:
            try:
                syscall_name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                syscall_name = 'Unknown'
        else:
            syscall_name = self.get_syscall_name(event.regs.rax)
            # push them to the stack
            self.syscall_stack[event.vcpu_nb].append(syscall_name)
        syscall = Syscall(event, syscall_name)
        return syscall

    def get_syscall_name(self, rax):
        ssn = rax & 0xFFF
        idx = (rax & 0x3000) >> 12
        try:
            syscall_name = self.sdt[idx]['ServiceTable'][ssn]
        except (KeyError, IndexError):
            syscall_name = 'Table{}!Unknown'.format(idx)
        return syscall_name
