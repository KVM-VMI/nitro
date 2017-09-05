import logging
import re

from ctypes import sizeof, c_void_p

from nitro.syscall import Syscall
from nitro.event import SyscallDirection
from nitro.libvmi import LibvmiError
from nitro.backends.linux.process import LinuxProcess
from nitro.backends.backend import Backend
from nitro.backends.linux.arguments import LinuxArgumentMap

# Technically, I do not think using this the way I do is correct since it might be different for the VM
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

    def __init__(self, domain, libvmi, listener, syscall_filtering=True):
        super().__init__(domain, libvmi, listener, syscall_filtering)
        self.sys_call_table_addr = self.libvmi.translate_ksym2v("sys_call_table")
        logging.debug("sys_call_table at %s", hex(self.sys_call_table_addr))

        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        self.syscall_stack = tuple([] for _ in range(self.nb_vcpu))

        self.tasks_offset = self.libvmi.get_offset("linux_tasks")
        self.mm_offset = self.libvmi.get_offset("linux_mm")
        self.pgd_offset = self.libvmi.get_offset("linux_pgd")

    def process_event(self, event):
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
            except IndexError:
                syscall = Syscall(event, "Unknown", "Unknown", process, None)
        else:
            try:
                name = self.get_syscall_name(event.regs.rax)
                args = LinuxArgumentMap(event, process)
                cleaned = clean_name(name) if name is not None else None
                syscall = Syscall(event, name, cleaned, process, args)
            except LibvmiError as error:
                logging.error("LinuxBackend: failed to get_syscall_name (LibvmiError)")
                raise error
            self.syscall_stack[event.vcpu_nb].append(syscall)
        self.dispatch_hooks(syscall)
        return syscall

    def get_syscall_name(self, rax):
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

