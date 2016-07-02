#!/usr/bin/env python3

"""Nitro.

Usage:
  nitro.py <pid>

Options:
  -h --help     Show this screen.

"""


import os
import sys
import re
import struct
import logging
import subprocess
import json
from pprint import pprint
from ctypes import *

from docopt import docopt
import libvirt


class Process:

    def __init__(self, cr3, cr3_vaddr):
        self.cr3 = cr3
        self.cr3_vaddr = cr3_vaddr

class Backend:

    def __init__(self):
        self.con = libvirt.open('qemu:///session')
        self.vm = self.con.lookupByName('winxp64') # hardcoded for now
        self.processes = {}

        # dump memory
        logging.debug('Taking Physical Memory dump ...')
        self.dump_path = 'winxp64.raw'
        flags = libvirt.VIR_DUMP_MEMORY_ONLY
        dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
        self.vm.coreDumpWithFormat(self.dump_path, dumpformat, flags)

        # call helper
        logging.debug('Getting symbols ...')
        subprocess.getoutput('python2 symbol_helper.py {}'.format(self.dump_path))
        with open('output.json') as f:
            jdata = json.load(f)
            self.nt_ssdt = {}
            self.win32k_ssdt = {}
            self.sdt = [self.nt_ssdt, self.win32k_ssdt]
            cur = None
            for e in jdata:
                if e[0] == 'r':
                    if e[1]["divider"] is not None:
                        # new table
                        m = re.match(r'Table ([0-9]) @ .*', e[1]["divider"])
                        idx = int(m.group(1))
                        cur_ssdt = self.sdt[idx]
                    else:
                        entry = e[1]["entry"]
                        full_name = e[1]["symbol"]["symbol"]
                        m = re.match(r'.*!(\w*)(\+.*)?', full_name)
                        name = m.group(1)
                        # add entry  to our ssdt
                        logging.debug('SSDT [{}] -> [{}]'.format(entry, name))
                        cur_ssdt[entry] = name



    def new_event(self, event):
        if event.event_type == Event.KVM_NITRO_EVENT_SYSCALL:
            self.new_syscall(event)
        # get process
        #p = None
        #cr3 = event.sregs.cr3
        #try:
        #    p = self.processes[cr3]
        #except KeyError:
        #    p = self.search_process(cr3)

    def new_syscall(self, event):
        logging.debug(event)
        ssn = event.regs.rax & 0xFFF
        idx = (event.regs.rax & 0x3000) >> 12
        logging.debug(self.sdt[idx][ssn])


    def search_process(self, cr3):
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


class DTable(Structure):
    _fields_ = [
                ('base', c_ulonglong),
                ('limit', c_ushort),
                ('padding', c_ushort * 3),
            ]

class Segment(Structure):
    _fields_ = [
                ('base', c_ulonglong),
                ('limit', c_uint),
                ('selector', c_ushort),
                ('type', c_ubyte),
                ('present', c_ubyte),
                ('dpl', c_ubyte),
                ('db', c_ubyte),
                ('s', c_ubyte),
                ('l', c_ubyte),
                ('g', c_ubyte),
                ('avl', c_ubyte),
                ('unusable', c_ubyte),
                ('padding', c_ubyte),
            ]

class SRegs(Structure):
    _fields_ = [
                ('cs', Segment),
                ('ds', Segment),
                ('es', Segment),
                ('fs', Segment),
                ('gs', Segment),
                ('ss', Segment),
                ('tr', Segment),
                ('ldt', Segment),
                ('gdt', DTable),
                ('idt', DTable),
                ('cr0', c_ulonglong),
                ('cr2', c_ulonglong),
                ('cr3', c_ulonglong),
                ('cr4', c_ulonglong),
                ('cr8', c_ulonglong),
                ('efer', c_ulonglong),
                ('apic_base', c_ulonglong),
                ('interrupt_bitmap', c_ulonglong * ((256 + 63) // 64)),
            ]

class Regs(Structure):
    _fields_ = [
                ('rax', c_ulonglong),
                ('rbx', c_ulonglong),
                ('rcx', c_ulonglong),
                ('rdx', c_ulonglong),
                ('rsi', c_ulonglong),
                ('rdi', c_ulonglong),
                ('rsp', c_ulonglong),
                ('rbp', c_ulonglong),
                ('r8', c_ulonglong),
                ('r9', c_ulonglong),
                ('r10', c_ulonglong),
                ('r11', c_ulonglong),
                ('r12', c_ulonglong),
                ('r13', c_ulonglong),
                ('r14', c_ulonglong),
                ('r15', c_ulonglong),
                ('rip', c_ulonglong),
                ('rflags', c_ulonglong),
            ]


class Event:

    KVM_NITRO_EVENT_ERROR = 1
    KVM_NITRO_EVENT_SYSCALL = 2
    KVM_NITRO_EVENT_SYSRET = 3

    def __init__(self, event_type, regs, sregs):
        if event_type == self.KVM_NITRO_EVENT_ERROR:
            raise RuntimeError()
        self.event_type = event_type
        self.regs = regs
        self.sregs = sregs

    def __str__(self):
        if self.event_type == self.KVM_NITRO_EVENT_SYSCALL:
            return "SYSCALL rax = {}, cr3 = {}".format(hex(self.regs.rax),
                    hex(self.sregs.cr3))
        else:
            return "SYSRET"



class Nitro:

    def __init__(self, pid):
        self.pid = pid
        logging.debug('Loading libnitro.so')
        self.libnitro = cdll.LoadLibrary('./libnitro/libnitro.so')


    def __enter__(self):
        logging.debug('Initializing KVM')
        self.libnitro.init_kvm()
        logging.debug('Attaching to the VM')
        self.libnitro.attach_vm(c_int(self.pid))
        logging.debug('Attaching to VCPUs')
        self.libnitro.attach_vcpus()
        logging.debug('Setting Traps')
        self.libnitro.set_syscall_trap(True)
        return self

    def __exit__(self, type, value, traceback):
        logging.debug('Unsetting Traps')
        self.libnitro.set_syscall_trap(False)
        logging.debug('Closing KVM')
        self.libnitro.close_kvm()


    def listen(self):
        while 1:
            try:
                event = self.libnitro.get_event(0)
                regs = Regs()
                sregs = SRegs()
                self.libnitro.get_regs(0, byref(regs))
                self.libnitro.get_sregs(0, byref(sregs))

                e = Event(event, regs, sregs)

                yield(e)
                self.libnitro.continue_vm(0)
            except KeyboardInterrupt:
                break

def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    pid = int(args['<pid>'])
    logging.debug('pid = {}'.format(pid))

    backend = Backend()
    with Nitro(pid) as nitro:
        for event in nitro.listen():
            backend.new_event(event)

if __name__ == '__main__':
    init_logger()
    main(docopt(__doc__))
