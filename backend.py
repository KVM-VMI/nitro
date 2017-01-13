import logging
import re
import os
import libvirt
import subprocess
import shutil
import json
from tempfile import NamedTemporaryFile

GETSYMBOLS_SCRIPT = 'symbols.py'


class Backend:

    def __init__(self, domain):
        self.domain = domain
        self.syscall_stack = []
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
