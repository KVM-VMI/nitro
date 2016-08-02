from ctypes import *

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
            return "SYSCALL"
        else:
            return "SYSRET "


