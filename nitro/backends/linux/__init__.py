import logging

from nitro.syscall import Syscall
from nitro.event import SyscallDirection

from ..common import Backend, ArgumentMap

class Linux(Backend):
    __slots__ = (
        "sys_call_table_addr",
        "nb_vcpu",
        "syscall_stack"
    )

    def __init__(self, domain):
        super().__init__(domain)
        self.sys_call_table_addr = self.libvmi.translate_ksym2v("sys_call_table")
        logging.debug("sys_call_table at {:f}".format(self.sys_call_table_addr))

        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        self.syscall_stack = [[] for _ in range(self.nb_vcpu)]

    def process_event(self, event):
        if event.direction == SyscallDirection.exit:
            try:
                name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                name = None
        else:
            name = self.get_syscall_name(event.regs.rax)
            self.syscall_stack[event.vcpu_nb].append(name)
        args = LinuxArgumentMap(event, name, None, self.nitro)
        syscall = Syscall(event, name, None, self.nitro, args)
        self.dispatch_hooks(syscall)
        return syscall

    def get_syscall_name(self, rax):
        assert 0 <= rax <= 1000 # This is not really necessary or even a
                                # productive sanity check and should likely be
                                # removed
        p_addr = self.sys_call_table_addr + (rax * 8) # address of the pointer within the sys_call_table array
        addr = self.libvmi.read_addr_va(p_addr, 0) # get the address of the procedure
        return self.libvmi.translate_v2ksym(addr) # translate the address into a name


class LinuxArgumentMap(ArgumentMap):
    def __init__(self, event, name, process, nitro):
        super().__init__(event, name, process, nitro)

    def __getitem__(self, index):
        raise NotImplementedError()

    def __setitem__(self, index, value):
        raise NotImplementedError()
