import logging

from ctypes import sizeof, c_void_p

from nitro.syscall import Syscall
from nitro.event import SyscallDirection
from nitro.process import Process

from ..common import Backend, ArgumentMap

# Technically, I do not think using this the way I do is correct
VOID_P_SIZE = sizeof(c_void_p)

class Linux(Backend):
    __slots__ = (
        "sys_call_table_addr",
        "nb_vcpu",
        "syscall_stack",
        "tasks_offset",
        "pid_offset",
        "mm_offset",
        "pgd_offset",
        "name_offset"
    )

    def __init__(self, domain):
        super().__init__(domain)
        self.sys_call_table_addr = self.libvmi.translate_ksym2v("sys_call_table")
        logging.debug("sys_call_table at {:f}".format(self.sys_call_table_addr))

        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        self.syscall_stack = [[] for _ in range(self.nb_vcpu)]

        self.tasks_offset = self.libvmi.get_offset("linux_tasks")
        self.pid_offset = self.libvmi.get_offset("linux_pid")
        self.mm_offset = self.libvmi.get_offset("linux_mm")
        self.pgd_offset = self.libvmi.get_offset("linux_pgd")
        self.name_offset = self.libvmi.get_offset("linux_name")

    def process_event(self, event):
        process = self.associate_process(event.sregs.cr3)
        if event.direction == SyscallDirection.exit:
            try:
                name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                name = None
        else:
            name = self.get_syscall_name(event.regs.rax)
            self.syscall_stack[event.vcpu_nb].append(name)
        args = LinuxArgumentMap(event, name, process, self.nitro)
        syscall = Syscall(event, name, process, self.nitro, args)
        self.dispatch_hooks(syscall)
        return syscall

    def get_syscall_name(self, rax):
        assert 0 <= rax <= 1000 # This is not really necessary or even a
                                # productive sanity check and should likely be
                                # removed
        p_addr = self.sys_call_table_addr + (rax * VOID_P_SIZE) # address of the pointer within the sys_call_table array
        addr = self.libvmi.read_addr_va(p_addr, 0) # get the address of the procedure
        return self.libvmi.translate_v2ksym(addr) # translate the address into a name

    def associate_process(self, cr3):
        """Get Process associated with CR3"""
        head = self.libvmi.translate_ksym2v("init_task") # get the address of swapper's task_struct
        next = head
        while True: # Maybe this should have a sanity check stopping it
            pid = self.libvmi.read_32(next + self.pid_offset, 0)

            mm = self.libvmi.read_addr_va(next + self.mm_offset, 0)
            if not mm:
                mm = self.libvmi.read_addr_va(next + self.mm_offset + VOID_P_SIZE, 0)
            if mm:
                pgd = self.libvmi.read_addr_va(mm + self.pgd_offset, 0)
                pgd_phys_addr = self.libvmi.translate_kv2p(pgd)
                if cr3 == pgd_phys_addr:
                    # Eventually, I would like to look for the executable name from mm->exe_file->f_path
                    name = self.libvmi.read_str_va(next + self.name_offset, 0)
                    process = Process(cr3, next, name, pid, self.libvmi)
                    return process
            else:
                logging.debug("no mm found for pid {}".format(pid))
            next = self.libvmi.read_addr_va(next + self.tasks_offset, 0) - self.tasks_offset
            if next == head:
                break

class LinuxArgumentMap(ArgumentMap):
    def __init__(self, event, name, process, nitro):
        super().__init__(event, name, process, nitro)

    def __getitem__(self, index):
        raise NotImplementedError()

    def __setitem__(self, index, value):
        raise NotImplementedError()
