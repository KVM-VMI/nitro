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

class NitroEvent(Structure):
    _fields_ = [
                ('present', c_bool),
                ('direction', c_uint),
                ('type', c_uint),
            ]


class Event:

    DIRECTION_ENTER = 0
    DIRECTION_EXIT = 1
    TYPE_SYSENTER = 0
    TYPE_SYSCALL = 1

    def __init__(self, nitro_event, regs, sregs, vcpu_nb=0):
        self.nitro_event = nitro_event
        self.regs = regs
        self.sregs = sregs
        self.vcpu_nb = vcpu_nb

    def __str__(self):
        type_msg = 'SYSENTER' if self.nitro_event.type == self.TYPE_SYSENTER else 'SYSCALL'
        dir_msg = 'ENTER' if self.nitro_event.direction == self.DIRECTION_ENTER else 'EXIT'
        cr3 = hex(self.sregs.cr3)
        rax = hex(self.regs.rax)
        msg = 'vcpu: {} - type: {} - direction: {} - cr3: {} - rax: {}'.format(self.vcpu_nb, type_msg, dir_msg, cr3, rax)
        return msg
        

    def direction(self):
        if self.nitro_event.direction == self.DIRECTION_ENTER:
            return 'ENTER'
        else:
            return 'EXIT'

    def display(self):
        cr3 = hex(self.sregs.cr3)
        rax = hex(self.regs.rax)
        if self.nitro_event.direction == self.DIRECTION_ENTER:
            return "SYSCALL cr3 {} - rax {}".format(cr3, rax)
        else:
            return "SYSRET  cr3 {} - rax {}".format(cr3, rax)


