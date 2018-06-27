"""
Backend for extracting information about system calls from Linux guests.
"""

import logging
import re

from ctypes import sizeof, c_void_p

from libvmi import LibvmiError
from nitro.syscall import Syscall
from nitro.event import SyscallDirection
from nitro.backends.linux.process import LinuxProcess
from nitro.backends.backend import Backend
from nitro.backends.linux.arguments import LinuxArgumentMap

# Technically, I do not think using this the way
#  I do is correct since it might be different for the VM
VOID_P_SIZE = sizeof(c_void_p)

HANDLER_NAME_REGEX = re.compile(r"^(SyS|sys)_(?P<name>.+)")

MAX_SYSTEM_CALL_COUNT = 1024

class LinuxBackend(Backend):
    """Extract information about system calls produced by the guest. This backend
    support 64-bit Linux guests."""

    __slots__ = (
        "sys_call_table_addr",
        "nb_vcpu",
        "syscall_stack",
        "tasks_offset",
        "syscall_names",
        "mm_offset",
        "pgd_offset",
    )

    def __init__(self, domain, libvmi, listener, syscall_filtering=True):
        super().__init__(domain, libvmi, listener, syscall_filtering)
        self.sys_call_table_addr = self.libvmi.translate_ksym2v("sys_call_table")
        logging.debug("sys_call_table at %s", hex(self.sys_call_table_addr))

        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        self.syscall_stack = tuple([] for _ in range(self.nb_vcpu))

        self.syscall_names = self.build_syscall_name_map()

        self.tasks_offset = self.libvmi.get_offset("linux_tasks")
        self.mm_offset = self.libvmi.get_offset("linux_mm")
        self.pgd_offset = self.libvmi.get_offset("linux_pgd")

    def process_event(self, event):
        """
        Process ``NitroEvent`` and return a matching ``Systemcall``. This function
        analyzes system state and, based on it, produces a new ``Systemcall``
        that contains higher-level information about the system call that is
        being processed.

        :param NitroEvent event: event to be analyzed
        :returns: system call based on ``event``.
        :rtype: Systemcall
        """

        # Clearing these caches is really important since otherwise we will end
        # up with incorrect memory references. Unfortunatelly, this will also
        # make the backend slow. In my limited testing it seems that only
        # clearing v2p cache works most of the time but I am sure issues will
        # arise.
        self.libvmi.v2pcache_flush()
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()

        process = self.associate_process(event.sregs.cr3)
        if event.direction == SyscallDirection.exit:
            try:
                syscall = self.syscall_stack[event.vcpu_nb].pop()
                syscall.event = event
            except IndexError:
                syscall = Syscall(event, "Unknown", "Unknown", process, None)
        else:
            # Maybe we should catch errors from associate_process
            name = self.get_syscall_name(event.regs.rax)
            args = LinuxArgumentMap(event, process)
            cleaned = clean_name(name) if name is not None else None
            syscall = Syscall(event, name, cleaned, process, args)
            self.syscall_stack[event.vcpu_nb].append(syscall)
        self.dispatch_hooks(syscall)
        return syscall

    def get_syscall_name(self, rax):
        """
        Return name of the system call handler associated with ``rax``.

        :param int rax: index into system call table.
        :returns: system call handler name
        :rtype: str
        """
        # address of the pointer within the sys_call_table array
        p_addr = self.sys_call_table_addr + (rax * VOID_P_SIZE)
        # get the address of the procedure
        addr = self.libvmi.read_addr_va(p_addr, 0)
        # translate the address into a name
        return self.libvmi.translate_v2ksym(addr)

    def build_syscall_name_map(self):
        # Its a bit difficult to know where the system call table ends, here we
        # do something kind of risky and read as long as translate_v2ksym
        # returns something that looks like a system call handler.
        mapping = {}
        for i in range(0, MAX_SYSTEM_CALL_COUNT):
            p_addr = self.sys_call_table_addr + (i * VOID_P_SIZE)
            try:
                addr = self.libvmi.read_addr_va(p_addr, 0)
                symbol = self.libvmi.translate_v2ksym(addr)
            except LibvmiError as error:
                logging.critical("Failed to build syscall name map")
                raise error
            else:
                if symbol is not None:
                    mapping[symbol] = i
                else:
                    break
        return mapping

    def find_syscall_nb(self, syscall_name):
        # What about thos compat_* handlers?
        handler_regexp = re.compile(r"^(SyS|sys)_{}$".format(re.escape(syscall_name)))
        for full_name, ind in self.syscall_names.items():
            if handler_regexp.match(full_name) is not None:
                return ind

    def associate_process(self, cr3):
        """
        Get ``LinuxProcess`` associated with ``cr3``
        :params int cr3: cr3 value
        :returns: process associated with ``cr3``
        :rtype: LinuxProcess
        """
        head = self.libvmi.translate_ksym2v("init_task") # get the address of swapper's task_struct
        next_ = head
        while True: # Maybe this should have a sanity check stopping it
            mm = self.libvmi.read_addr_va(next_ + self.mm_offset, 0)
            if not mm:
                mm = self.libvmi.read_addr_va(next_ + self.mm_offset + VOID_P_SIZE, 0)
            if mm:
                pgd = self.libvmi.read_addr_va(mm + self.pgd_offset, 0)
                pgd_phys_addr = self.libvmi.translate_kv2p(pgd)
                if cr3 == pgd_phys_addr:
                    # Eventually, I would like to look for the executable name from mm->exe_file->f_path
                    return LinuxProcess(self.libvmi, cr3, next_)
            else:
                #logging.debug("missing mm")
                pass
            next_ = self.libvmi.read_addr_va(next_ + self.tasks_offset, 0) - self.tasks_offset
            if next_ == head:
                break

    def define_hook(self, name, callback, direction=SyscallDirection.enter):
        super().define_hook(name, callback, direction)
        if self.syscall_filtering:
            self.add_syscall_filter(name)

    def undefine_hook(self, name, direction=SyscallDirection.enter):
        super().undefine_hook(name, direction)
        if self.syscall_filtering:
            self.remove_syscall_filter(name)

    def add_syscall_filter(self, syscall_name):
        syscall_nb = self.find_syscall_nb(syscall_name)
        if syscall_nb is None:
            raise RuntimeError(
                'Unable to find syscall number for %s' % syscall_name)
        self.listener.add_syscall_filter(syscall_nb)

    def remove_syscall_filter(self, syscall_name):
        syscall_nb = self.find_syscall_nb(syscall_name)
        if syscall_nb is None:
            raise RuntimeError(
                'Unable to find syscall number for %s' % syscall_name)
        self.listener.remove_syscall_filter(syscall_nb)


def clean_name(name):
    matches = HANDLER_NAME_REGEX.search(name)
    return matches.group("name") if matches is not None else name
