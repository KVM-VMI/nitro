import os
import logging
from ctypes import *
from ioctl_opt import IO, IOR, IOW

KVMIO = 0xAE
NITRO_MAX_VCPUS = 64

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
                ('regs', Regs),
                ('sregs', SRegs),
            ]

class NitroVCPUs(Structure):
    _fields_ = [
                ('num_vcpus', c_int),
                ('ids', c_int * NITRO_MAX_VCPUS),
                ('fds', c_int * NITRO_MAX_VCPUS),
            ]


class IOCTL():

    LIBC_6 = 'libc.so.6'

    def __init__(self):
        self.libc = CDLL(self.LIBC_6)
        self.fd = None

    def make_ioctl(self, request, arg):
        if not self.fd:
            raise Exception('Uninitialized FD for ioctl')
        return self.libc.ioctl(self.fd, request, arg)

    def close(self):
        os.close(self.fd)

class KVM(IOCTL):

    KVM_NODE = '/dev/kvm'
    KVM_NITRO_ATTACH_VM = IOW(KVMIO, 0xE1, c_int)

    def __init__(self):
        super().__init__()
        self.kvm_file = open(self.KVM_NODE, 'r+')
        self.fd = self.kvm_file.fileno()

    def attach_vm(self, pid):
        logging.debug('attach_vm PID = {}'.format(pid))
        c_pid = c_int(pid)
        r = self.make_ioctl(self.KVM_NITRO_ATTACH_VM, byref(c_pid))
        return r

class VM(IOCTL):

    KVM_NITRO_ATTACH_VCPUS = IOR(KVMIO, 0xE2, NitroVCPUs)
    KVM_NITRO_SET_SYSCALL_TRAP = IOW(KVMIO, 0xE3, c_bool)

    def __init__(self, vm_fd):
        super().__init__()
        self.fd = vm_fd
        self.vcpus_struct = NitroVCPUs()

    def attach_vcpus(self):
        logging.debug('attach_vcpus')
        self.make_ioctl(self.KVM_NITRO_ATTACH_VCPUS, byref(self.vcpus_struct))
        vcpus = [VCPU(i, self.vcpus_struct.fds[i]) for i in range(self.vcpus_struct.num_vcpus)]
        return vcpus

    def set_syscall_trap(self, enabled):
        logging.debug('set_syscall_trap {}'.format(enabled))
        c_enabled = c_bool(enabled)
        r = self.make_ioctl(self.KVM_NITRO_SET_SYSCALL_TRAP, byref(c_enabled))
        return r

class VCPU(IOCTL):

    KVM_NITRO_GET_EVENT = IOR(KVMIO, 0xE5, NitroEventStr)
    KVM_NITRO_CONTINUE = IO(KVMIO, 0xE6)

    def __init__(self, vcpu_nb, vcpu_fd):
        super().__init__()
        self.vcpu_nb = vcpu_nb
        self.fd = vcpu_fd

    def get_event(self):
        # logging.debug('get_event {}'.format(self.vcpu_nb))
        nitro_ev = NitroEventStr()
        self.make_ioctl(self.KVM_NITRO_GET_EVENT, byref(nitro_ev))
        return nitro_ev

    def continue_vm(self):
        # logging.debug('continue_vm {}'.format(self.vcpu_nb))
        return self.make_ioctl(self.KVM_NITRO_CONTINUE, 0)

