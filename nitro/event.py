from enum import Enum

class SyscallDirection(Enum):
    enter = 0
    exit = 1

class SyscallType(Enum):
    sysenter = 0
    syscall = 1

class NitroEvent:

    __slots__ = (
        'direction',
        'type',
        'regs',
        'sregs',
        'vcpu_nb',
    )

    def __init__(self, nitro_event_str, vcpu_nb=0):
        self.direction = SyscallDirection(nitro_event_str.direction)
        self.type = SyscallType(nitro_event_str.type)
        self.regs = nitro_event_str.regs
        self.sregs = nitro_event_str.sregs
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

