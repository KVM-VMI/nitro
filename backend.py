import sys
import os
import re
import subprocess
import json
import logging
import struct

import libvirt

from event import Event

class Process:

    def __init__(self, cr3, cr3_vaddr):
        self.cr3 = cr3
        self.cr3_vaddr = cr3_vaddr

class Backend:

    def __init__(self, symbols=True):
        self.con = libvirt.open('qemu:///session')
        self.vm = self.con.lookupByName('win7x64') # hardcoded for now
        self.processes = {}

        self.symbols = symbols
        if self.symbols:
            # dump memory
            logging.debug('Taking Physical Memory dump ...')
            self.dump_path = 'dump.raw'
            flags = libvirt.VIR_DUMP_MEMORY_ONLY
            dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
            self.vm.coreDumpWithFormat(self.dump_path, dumpformat, flags)

            # call helper
            logging.debug('Getting symbols ...')
            subprocess.getoutput('python2 symbols.py {}'.format(self.dump_path))
            with open('output.json') as f:
                jdata = json.load(f)
                # loading ssdt entries
                self.nt_ssdt = {}
                self.win32k_ssdt = {}
                self.sdt = [self.nt_ssdt, self.win32k_ssdt]
                cur = None
                for e in jdata:
                    if isinstance(e, list) and e[0] == 'r':
                        if e[1]["divider"] is not None:
                            # new table
                            m = re.match(r'Table ([0-9]) @ .*', e[1]["divider"])
                            idx = int(m.group(1))
                            cur_ssdt = self.sdt[idx]
                        else:
                            entry = e[1]["entry"]
                            full_name = e[1]["symbol"]["symbol"]
                            m = re.match(r'(.*)(\+.*)?', full_name)
                            name = m.group(1)
                            # add entry  to our ssdt
                            logging.debug('SSDT [{}] -> [{}]'.format(entry, name))
                            cur_ssdt[entry] = name
                # loading pshead (last entry)
                pshead = jdata[-1]['PsActiveProcessHead']
                self.pshead_flink = int(pshead['Flink'], 16)
                self.pshead_blink = int(pshead['Blink'], 16)
                logging.debug(pshead)

    def new_event(self, event):
        logging.debug(event)
        if event.event_type == Event.KVM_NITRO_EVENT_SYSCALL:
            self.new_syscall(event)
        # get process
        p = None
        cr3 = event.sregs.cr3
        try:
            p = self.processes[cr3]
        except KeyError:
            p = self.walk_eprocess(cr3)

    def new_syscall(self, event):
        ssn = event.regs.rax & 0xFFF
        idx = (event.regs.rax & 0x3000) >> 12
        if self.symbols:
            logging.debug(self.sdt[idx][ssn])


    def walk_eprocess(self, cr3):
        flink = self.pshead_flink

        while flink != self.pshead_blink:
            logging.debug('Walking EProcess {}'.format(hex(flink)))
            # read new flink
            content = self.vm.memoryPeek(flink, 8, libvirt.VIR_MEMORY_VIRTUAL)
            logging.debug(content)
            flink, *rest = struct.unpack('@P', content)


    def search_process_memory(self, cr3):
        logging.debug('Searching for CR3 = {}'.format(hex(cr3)))
        start = 0
        size = 1024 * 1024
        while True:
            logging.debug('Searching at {}'.format(hex(start)))
            content = self.vm.memoryPeek(start, size, libvirt.VIR_MEMORY_VIRTUAL)
            b_cr3 = struct.pack('@P', cr3)
            m = re.search(b_cr3, content)
            if m:
                cr3_vaddr = start + m.start()
                logging.debug('Found CR3 at {} ({})'.format(hex(cr3_vaddr), m.start()))
                p = Process(cr3, cr3_vaddr)
                self.processes[cr3] = p
                return p
            start += size



