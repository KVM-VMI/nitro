import sys
import os
import re
import subprocess
import commands
import json
import logging
import struct

import libvirt
import pyvmi

from event import Event
from hooks import Hooks

class SyscallContext:

    def __init__(self, event, process, syscall_name):
        self.event = event
        self.process = process
        self.syscall_name = syscall_name

    def __str__(self):
        return '[{}] {} -> {}'.format(self.event, self.process.name, self.syscall_name)


class VM:

    def __init__(self, vm_name):
        self.con = libvirt.open('qemu:///system')
        self.domain = self.con.lookupByName(vm_name)

    def pmem_dump(self, path):
        flags = libvirt.VIR_DUMP_MEMORY_ONLY
        dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
        self.domain.coreDumpWithFormat(path, dumpformat, flags)

    def vmem_read(self, addr, size):
        content = self.domain.memoryPeek(addr, size, libvirt.VIR_MEMORY_VIRTUAL)
        return content

class Process:

    def __init__(self, cr3, start_eproc, name, pid):
        self.cr3 = cr3
        self.start_eproc = start_eproc
        self.name = name
        self.pid = pid

class Backend:

    def __init__(self, vm_name, arch):
        self.ptr_size = int(arch / 8)
        self.processes = {}
        self.sys_stack = []
        self.vm = VM(vm_name)
        self.vmi = pyvmi.init(vm_name, "complete")
        self.hooks = Hooks(self.vmi)
        # dump memory
        logging.debug('Taking Physical Memory dump ...')
        self.dump_path = 'dump.raw'
        self.vm.pmem_dump(self.dump_path)
        # call helper
        logging.debug('Getting symbols ...')
        # check virtualenv
        venv_python = os.path.join('venv', 'bin', 'python')
        if not os.path.isfile(venv_python):
            logging.debug('Please install a virtualenv "venv" with rekall')
            sys.exit(1)
        commands.getoutput('{} symbols.py {}'.format(venv_python, self.dump_path))
        with open('output.json') as f:
            jdata = json.load(f)
            # loading ssdt entries
            self.nt_ssdt = {'ServiceTable' : {}, 'ArgumentTable' : {}}
            self.win32k_ssdt = {'ServiceTable' : {}, 'ArgumentTable' : {}}
            self.sdt = [self.nt_ssdt, self.win32k_ssdt]
            cur = None
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
                        m = re.match(r'(.*)(\+.*)?', full_name)
                        name = m.group(1)
                        # add entry  to our ssdt
                        cur_ssdt[entry] = name
            # loading kernel symbols addresses
            self.kernel_symbols = jdata[-1]
            logging.debug(self.kernel_symbols)
        # remove dump and json file
        os.remove('dump.raw')
        os.remove('output.json')


    def new_event(self, event):
        ctxt = None
        if event.event_type == Event.KVM_NITRO_EVENT_SYSRET:
            # check syscall stack
            try:
                ctxt = self.sys_stack.pop()
                ctxt.event = event
            except IndexError:
                # logging.debug(event)
                return
        else:
            # create syscall context
            cr3 = event.sregs.cr3
            # get process
            process = self.associate_process(cr3)
            # get syscall name
            ssn = event.regs.rax & 0xFFF
            idx = (event.regs.rax & 0x3000) >> 12
            syscall = self.sdt[idx]['ServiceTable'][ssn]
            m = re.match(r'.*!(.*)', syscall)
            syscall_name = m.group(1)
            ctxt = SyscallContext(event, process, syscall_name)
            # push on stack
            self.sys_stack.append(ctxt)

        self.hooks.dispatch(ctxt)

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
        flink = self.vmi.read_addr_ksym('PsActiveProcessHead')
        
        while flink != self.kernel_symbols['PsActiveProcessHead']:
            # get start of EProcess
            start_eproc = flink - self.kernel_symbols['ActiveProcessLinks_off']
            # move to start of DirectoryTableBase
            directory_table_base_off = start_eproc + self.kernel_symbols['DirectoryTableBase_off']
            # read directory_table_base
            directory_table_base = self.vmi.read_addr_va(directory_table_base_off, 0)
            # compare to our cr3
            if cr3 == directory_table_base:
                # get name
                image_file_name_off = start_eproc + self.kernel_symbols['ImageFileName_off']
                content = self.vmi.read_va(image_file_name_off, 0, 15)
                image_file_name = content.rstrip(b'\0').decode('utf-8')
                # get pid
                unique_processid_off = start_eproc + 0x84
                pid = self.vmi.read_addr_va(unique_processid_off, 0)
                eprocess = Process(cr3, start_eproc, image_file_name, pid)
                return eprocess

            # read new flink
            flink = self.vmi.read_addr_va(flink, 0)



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

