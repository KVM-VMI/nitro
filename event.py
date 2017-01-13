from ctypes import *
from enum import Enum

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

class NitroEventStr(Structure):
    _fields_ = [
                ('present', c_bool),
                ('direction', c_uint),
                ('type', c_uint),
            ]

class SyscallDirection(Enum):
    enter = 0
    exit = 1

class SyscallType(Enum):
    sysenter = 0
    syscall = 1

class NitroEvent:

    def __init__(self, nitro_event_str, regs, sregs, vcpu_nb=0):
        self.direction = SyscallDirection(nitro_event_str.direction)
        self.type = SyscallType(nitro_event_str.type)
        self.regs = regs
        self.sregs = sregs
        self.vcpu_nb = vcpu_nb

    def __str__(self):
        type_msg = self.type.name.upper()
        dir_msg = self.direction.name.upper()
        cr3 = hex(self.sregs.cr3)
        rax = hex(self.regs.rax)
        msg = 'vcpu: {} - type: {} - direction: {} - cr3: {} - rax: {}'.format(self.vcpu_nb, type_msg, dir_msg, cr3, rax)
        return msg

    def info(self):
        info = {}
        info['vcpu'] = self.vcpu_nb
        info['type'] = self.type.name
        info['direction'] = self.direction.name
        info['cr3'] = hex(self.sregs.cr3)
        info['rax'] = hex(self.regs.rax)
        return info

