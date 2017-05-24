import struct
from enum import Enum
from nitro.event import SyscallDirection, SyscallType


class SyscallArgumentType(Enum):
    register = 0
    memory = 1


class ArgumentMap:

    CONVENTION = {
        SyscallType.syscall: [
            (SyscallArgumentType.register, 'rcx'),
            (SyscallArgumentType.register, 'rdx'),
            (SyscallArgumentType.register, 'r8'),
            (SyscallArgumentType.register, 'r9'),
            (SyscallArgumentType.memory, 0),
            (SyscallArgumentType.memory, 1),
            (SyscallArgumentType.memory, 2),
            (SyscallArgumentType.memory, 3),
            (SyscallArgumentType.memory, 4),
            (SyscallArgumentType.memory, 5),
            (SyscallArgumentType.memory, 6),
        ],
    }

    ARG_SIZE = {
        SyscallType.syscall: 'P',   # x64 -> 8 bytes
        SyscallType.sysenter: 'I'   # x32 -> 4 bytes
    }

    __slots__ = (
        'event',
        'process',
        'nitro',
        'arg_size_format',
    )

    def __init__(self, event, process, nitro):
        self.event = event
        self.process = process
        self.nitro = nitro
        self.arg_size_format = self.ARG_SIZE[self.event.type]

    def __getitem__(self, index):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError:
            raise RuntimeError('Unknown covention')
        except IndexError:
            raise RuntimeError('Syscall argument index out of bounds')
        if arg_type == SyscallArgumentType.register:
            try:
                value = getattr(self.event.regs, opaque)
            except AttributeError:
                raise RuntimeError('Unknown register')
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            try:
                addr = self.event.regs.rsp + (opaque * size)
            except AttributeError:
                raise RuntimeError('Unknown register')
            value, *rest = struct.unpack(self.arg_size_format, self.process.read_memory(addr, size))
        return value

    def __setitem__(self, index, value):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError:
            raise RuntimeError('Unknown covention')
        except IndexError:
            raise RuntimeError('Syscall argument index out of bounds')
        if arg_type == SyscallArgumentType.register:
            try:
                setattr(self.event.regs, opaque, value)
            except AttributeError:
                raise RuntimeError('Unknwon register')
            else:
                self.nitro.vcpus_io[self.event.vcpu_nb].set_regs(self.event.regs)
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            try:
                addr = self.event.regs.rsp + (opaque * size)
            except AttributeError:
                raise RuntimeError('Unkown register')
            buffer = struct.pack(self.arg_size_format, value)
            import pdb; pdb.set_trace()
            self.process.write_memory(addr, buffer)


class Syscall:

    __slots__ = (
        'event',
        'full_name',
        'name',
        'process',
        'hook',
        'nitro',
        'args',
    )

    def __init__(self, event, name, process, nitro):
        self.event = event
        self.full_name = name
        # clean rekall syscall name
        # full_name is 'nt!NtOpenFile'
        # name will be NtOpenFile
        *rest, self.name = self.full_name.split('!')
        self.process = process
        self.nitro = nitro
        self.args = ArgumentMap(self.event, self.process, self.nitro)
        self.hook = None

    def info(self):
        info = {}
        info['name'] = self.name
        info['event'] = self.event.info()
        if self.process:
            info['process'] = self.process.info()
        if self.hook:
            # user added information, if any hook has been set
            info['hook'] = self.hook
        return info
