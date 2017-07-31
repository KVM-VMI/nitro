import logging
import re

from ctypes import sizeof, c_void_p

from nitro.syscall import Syscall
from nitro.event import SyscallDirection
from nitro.libvmi import LibvmiError
from nitro.backends.linux.process import LinuxProcess
from nitro.backends.backend import Backend
from nitro.backends.linux.arguments import LinuxArgumentMap

# Technically, I do not think using this the way I do is correct
VOID_P_SIZE = sizeof(c_void_p)

HANDLER_NAME_REGEX = re.compile(r"^(SyS|sys)_(?P<name>.+)")

class LinuxBackend(Backend):
    __slots__ = (
        "sys_call_table_addr",
        "nb_vcpu",
        "syscall_stack",
        "tasks_offset",
        "mm_offset",
        "pgd_offset",
    )

    def __init__(self, domain, libvmi):
        super().__init__(domain, libvmi)
        self.sys_call_table_addr = self.libvmi.translate_ksym2v("sys_call_table")
        logging.debug("sys_call_table at %s", hex(self.sys_call_table_addr))

        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        self.syscall_stack = tuple([] for _ in range(self.nb_vcpu))

        self.tasks_offset = self.libvmi.get_offset("linux_tasks")
        self.mm_offset = self.libvmi.get_offset("linux_mm")
        self.pgd_offset = self.libvmi.get_offset("linux_pgd")

    def process_event(self, event):
        # Are all of these really necessary?
        # we seem to get all kinds of weird errors during shutdown if we do not flush there
        # However, flushing the caches slows down things so much that things start to break for other reasons
        #self.libvmi.v2pcache_flush()
        #self.libvmi.pidcache_flush()
        #self.libvmi.rvacache_flush()
        #self.libvmi.symcache_flush()
        try:
            process = self.associate_process(event.sregs.cr3)
        except LibvmiError as error:
            logging.error("LinuxBackend: failed to associate_process (LibvmiError)")
            raise error
        if event.direction == SyscallDirection.exit:
            try:
                name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                name = None
        else:
            try:
                name = self.get_syscall_name(event.regs.rax)
            except LibvmiError as error:
                logging.error("LinuxBackend: failed to get_syscall_name (LibvmiError)")
                raise error
            self.syscall_stack[event.vcpu_nb].append(name)
        args = LinuxArgumentMap(event, name, process)
        cleaned = clean_name(name) if name is not None else None
        syscall = Syscall(event, name, cleaned, process, args)
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

def clean_name(name):
    matches = HANDLER_NAME_REGEX.search(name)
    return matches.group("name") if matches is not None else name
