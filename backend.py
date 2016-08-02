import sys
import os
import re
import subprocess
import json
import logging
import struct

import libvirt

from event import Event

class SyscallContext:

    def __init__(self, event, process, syscall_name):
        self.event = event
        self.process = process
        self.syscall_name = syscall_name

    def __str__(self):
        return '[{}] {} -> {}'.format(self.event, self.process.name, self.syscall_name)


class VM:

    def __init__(self):
        self.con = libvirt.open('qemu:///session')
        self.domain = self.con.lookupByName('winxp') # hardcoded for now

    def pmem_dump(self, path):
        flags = libvirt.VIR_DUMP_MEMORY_ONLY
        dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
        self.domain.coreDumpWithFormat(path, dumpformat, flags)

    def vmem_read(self, addr, size):
        content = self.domain.memoryPeek(addr, size, libvirt.VIR_MEMORY_VIRTUAL)
        return content

class Process:

    def __init__(self, cr3, start_eproc, name):
        self.cr3 = cr3
        self.start_eproc = start_eproc
        self.name = name

class Backend:

    def __init__(self, symbols=True):
        self.symbols = symbols
        self.processes = {}
        self.sys_stack = []
        self.vm = VM()
        if self.symbols:
            # dump memory
            logging.debug('Taking Physical Memory dump ...')
            self.dump_path = 'dump.raw'
            self.vm.pmem_dump(self.dump_path)
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
                self.pshead = int(jdata[-1]['PsActiveProcessHead'], 16)
                logging.debug(hex(self.pshead))


    def new_event(self, event):
        ctxt = None
        if event.event_type == Event.KVM_NITRO_EVENT_SYSRET:
            # check syscall stack
            try:
                ctxt = self.sys_stack.pop()
                ctxt.event = event
            except IndexError:
                logging.debug(event)
                return
        else:
            # create syscall context
            cr3 = event.sregs.cr3
            # get process
            process = self.associate_process(cr3)
            # get syscall name
            ssn = event.regs.rax & 0xFFF
            idx = (event.regs.rax & 0x3000) >> 12
            syscall_name = self.sdt[idx][ssn]
            ctxt = SyscallContext(event, process, syscall_name)
            # push on stack
            self.sys_stack.append(ctxt)

        logging.debug(ctxt)


    def associate_process(self, cr3):
        p = None
        try:
            p = self.processes[cr3]
        except KeyError:
            p = self.find_eprocess(cr3)
            self.processes[cr3] = p
        return p

    def find_eprocess(self, cr3):
        # read pshead list_entry
        content = self.vm.vmem_read(self.pshead, 4)
        flink, *rest = struct.unpack('@I', content)
        
        while flink != self.pshead:
            # get start of EProcess
            start_eproc = flink - 0x88 # hardcoded winxp
            # move to start of DirectoryTableBase
            directory_table_base_off = start_eproc + 0x18
            # read directory_table_base
            content = self.vm.vmem_read(directory_table_base_off, 4)
            directory_table_base, *rest = struct.unpack('@I', content)
            # compare to our cr3
            if cr3 == directory_table_base:
                # get name
                image_file_name_off = start_eproc + 0x174
                content = self.vm.vmem_read(image_file_name_off, 16)
                image_file_name = content.rstrip(b'\0').decode('utf-8')
                eprocess = Process(cr3, start_eproc, image_file_name)
                return eprocess

            # read new flink
            content = self.vm.vmem_read(flink, 4)
            flink, *rest = struct.unpack('@I', content)



    def search_process_memory(self, cr3):
        logging.debug('Searching for CR3 = {}'.format(hex(cr3)))
        start = 0
        size = 1024 * 1024
        while True:
            logging.debug('Searching at {}'.format(hex(start)))
            content = self.vm.vmem_read(start, size)
            b_cr3 = struct.pack('@P', cr3)
            m = re.search(b_cr3, content)
            if m:
                cr3_vaddr = start + m.start()
                logging.debug('Found CR3 at {} ({})'.format(hex(cr3_vaddr), m.start()))
                p = Process(cr3, cr3_vaddr)
                self.processes[cr3] = p
                return p
            start += size

