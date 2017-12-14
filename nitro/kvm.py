"""
Low-level interface to KVM facilities. This module enables the use of
Nitro's enhanced KVM capabilities.
"""

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


class IOCTL:
    """Class for making IOCTL calls"""
    __slots__ = (
        'libc',
        'fd'
    )

    LIBC_6 = 'libc.so.6'

    def __init__(self):
        self.libc = CDLL(self.LIBC_6)
        self.fd = None

    def make_ioctl(self, request, arg):
        if not self.fd:
            raise Exception('Uninitialized FD for ioctl')
        return self.libc.ioctl(self.fd, request, arg)

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            # Bad file descriptor
            # already closed
            pass


class KVM(IOCTL):
    """Class for connecting to the KVM and attaching to virtual machines."""
    __slots__ = (
        'kvm_file'
    )

    KVM_NODE = '/dev/kvm'
    KVM_NITRO_ATTACH_VM = IOW(KVMIO, 0xE1, c_int)

    def __init__(self):
        super().__init__()
        self.kvm_file = open(self.KVM_NODE, 'r+')
        self.fd = self.kvm_file.fileno()

    def attach_vm(self, pid):
        """
        Attach to KVM virtual machine
        
        :param int pid: pid of the Qemu process to attach to.
        :raises: RuntimeError
        """
        logging.debug('attach_vm PID = %s', pid)
        c_pid = c_int(pid)
        r = self.make_ioctl(self.KVM_NITRO_ATTACH_VM, byref(c_pid))
        if r < 0:
            # invalid vm fd
            raise RuntimeError('Error: fail to attach to the VM')
        return r


class VM(IOCTL):
    """Class that allows low-level control of KVM virtual machines.

    VM makes it possible to attach to machine's virtual CPUs and add system call
    filters.
    """

    __slots__ = (
        'vcpus_struct',
        'syscall_filters'
    )

    #: Reguest for attaching to a virtual CPU
    KVM_NITRO_ATTACH_VCPUS = IOR(KVMIO, 0xE2, NitroVCPUs)
    #: Request for setting system call trap
    KVM_NITRO_SET_SYSCALL_TRAP = IOW(KVMIO, 0xE3, c_bool)
    #: Request for adding system call filter
    KVM_NITRO_ADD_SYSCALL_FILTER = IOR(KVMIO, 0xEB, c_ulonglong)
    #: Request for removing system call filter
    KVM_NITRO_REMOVE_SYSCALL_FILTER = IOR(KVMIO, 0xEC, c_ulonglong)

    def __init__(self, vm_fd):
        super().__init__()
        self.fd = vm_fd
        self.vcpus_struct = NitroVCPUs()
        self.syscall_filters = set()

    def attach_vcpus(self):
        """
        Attach to virtual CPUs

        :rtype: List of VCPUs
        """
        logging.debug('attach_vcpus')
        r = self.make_ioctl(self.KVM_NITRO_ATTACH_VCPUS,
                            byref(self.vcpus_struct))
        if r != 0:
            raise RuntimeError('Error: fail to attach to vcpus')
        vcpus = [VCPU(i, self.vcpus_struct.fds[i]) for i in
                 range(self.vcpus_struct.num_vcpus)]
        return vcpus

    def set_syscall_trap(self, enabled):
        logging.debug('set_syscall_trap %s', enabled)
        c_enabled = c_bool(enabled)
        r = self.make_ioctl(self.KVM_NITRO_SET_SYSCALL_TRAP, byref(c_enabled))
        return r

    def add_syscall_filter(self, syscall_nb):
        logging.debug('adding syscall filter on %s' % (hex(syscall_nb)))
        c_syscall_nb = c_ulonglong(syscall_nb)
        r = self.make_ioctl(self.KVM_NITRO_ADD_SYSCALL_FILTER,
                            byref(c_syscall_nb))
        if r != 0:
            raise RuntimeError('Error: fail to add syscall filter')
        self.syscall_filters.add(syscall_nb)
        return r

    def remove_syscall_filter(self, syscall_nb):
        logging.debug('removing syscall filter on %s' % (hex(syscall_nb)))
        c_syscall_nb = c_ulonglong(syscall_nb)
        r = self.make_ioctl(self.KVM_NITRO_REMOVE_SYSCALL_FILTER,
                            byref(c_syscall_nb))
        if r != 0:
            raise RuntimeError('Error: fail to remove syscall filter')
        self.syscall_filters.remove(syscall_nb)
        return r


class VCPU(IOCTL):
    """Class that allows controlling and inspecting the state of an individual virtual CPU."""

    __slots__ = (
        'vcpu_nb',
    )

    #: Request for retrieving event
    KVM_NITRO_GET_EVENT = IOR(KVMIO, 0xE5, NitroEventStr)
    #: Request to continue
    KVM_NITRO_CONTINUE = IO(KVMIO, 0xE6)
    #: Request to get register state
    KVM_NITRO_GET_REGS = IOR(KVMIO, 0xE7, Regs)
    #: Request to set register state
    KVM_NITRO_SET_REGS = IOW(KVMIO, 0xE8, Regs)
    #: Request to get special registers
    KVM_NITRO_GET_SREGS = IOR(KVMIO, 0xE9, SRegs)
    #: Request to set special registers
    KVM_NITRO_SET_SREGS = IOW(KVMIO, 0xEA, SRegs)

    def __init__(self, vcpu_nb, vcpu_fd):
        super().__init__()
        self.vcpu_nb = vcpu_nb
        self.fd = vcpu_fd

    def get_event(self):
        """
        Retrieve event from the virtual machine

        :rtype: NitroEventStr
        """
        # logging.debug('get_event %s, self.vcpu_nb)
        nitro_ev = NitroEventStr()
        ret = self.make_ioctl(self.KVM_NITRO_GET_EVENT, byref(nitro_ev))
        if ret != 0:
            raise ValueError("get_event failed on vcpu %d (%d)".format(self.vcpu_nb, ret))
        return nitro_ev

    def continue_vm(self):
        """Continue virtual machine execution"""
        # logging.debug('continue_vm %s', self.vcpu_nb)
        return self.make_ioctl(self.KVM_NITRO_CONTINUE, 0)

    def get_regs(self):
        """
        Get registers from the virtual machine.

        :rtype: Regs
        """
        regs = Regs()
        self.make_ioctl(self.KVM_NITRO_GET_REGS, byref(regs))
        return regs

    def get_sregs(self):
        """
        Get special registers from the virtual machine.

        :rtype: SRegs
        """
        sregs = SRegs()
        self.make_ioctl(self.KVM_NITRO_GET_SREGS, byref(sregs))
        return sregs

    def set_regs(self, regs):
        """
        Set registers for the virtual machine.

        :param Regs regs: Values for registers
        """
        ret = self.make_ioctl(self.KVM_NITRO_SET_REGS, byref(regs))
        return ret

    def set_sregs(self, sregs):
        """
        Set special registers for the virtual machine.

        :param SRegs sregs: Values for special registers
        """
        ret = self.make_ioctl(self.KVM_NITRO_SET_SREGS, byref(sregs))
        return ret
