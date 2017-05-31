import struct
from enum import Enum
from nitro.event import SyscallType


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
            (SyscallArgumentType.memory, 5),
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
        'modified',
    )

    def __init__(self, event, process, nitro):
        self.event = event
        self.process = process
        self.nitro = nitro
        self.arg_size_format = self.ARG_SIZE[self.event.type]
        self.modified = {}

    def __getitem__(self, index):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError:
            raise RuntimeError('Unknown covention')
        except IndexError:
            arg_type, opaque = self.CONVENTION[self.event.type][-1]
            opaque += index - len(self.CONVENTION[self.event.type]) + 1
        if arg_type == SyscallArgumentType.register:
            value = self.event.get_register(opaque)
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
            arg_type, opaque = self.CONVENTION[self.event.type][-1]
            opaque += index - len(self.CONVENTION[self.event.type]) + 1
        if arg_type == SyscallArgumentType.register:
            self.event.update_register(opaque, value)
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            try:
                addr = self.event.regs.rsp + (opaque * size)
            except AttributeError:
                raise RuntimeError('Unkown register')
            buffer = struct.pack(self.arg_size_format, value)
            self.process.write_memory(addr, buffer)
        self.modified[index] = value

    def info(self):
        return self.modified


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
        info = {
            'name': self.name,
            'event': self.event.info(),
        }
        if self.process:
            info['process'] = self.process.info()
        if self.hook:
            # user added information, if any hook has been set
            info['hook'] = self.hook
        modified = self.args.info()
        if modified:
            info['modified'] = modified
        return info
