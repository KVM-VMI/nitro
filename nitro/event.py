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
        'vcpu_io',
    )

    def __init__(self, nitro_event_str, vcpu_io):
        self.direction = SyscallDirection(nitro_event_str.direction)
        self.type = SyscallType(nitro_event_str.type)
        self.regs = nitro_event_str.regs
        self.sregs = nitro_event_str.sregs
        self.vcpu_io = vcpu_io
        self.vcpu_nb = self.vcpu_io.vcpu_nb

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

    def get_register(self, register):
        try:
            value = getattr(self.regs, register)
        except AttributeError:
            raise RuntimeError('Unknown register')
        else:
            return value

    def update_register(self, register, value):
        # get latest regs, to avoid replacing EIP by value before emulation
        self.regs = self.vcpu_io.get_regs()
        # update register if possible
        try:
            setattr(self.regs, register, value)
        except AttributeError:
            raise RuntimeError('Unknown register')
        else:
            # send new register to KVM VCPU
            self.vcpu_io.set_regs(self.regs)

