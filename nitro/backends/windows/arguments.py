import struct

from nitro.event import SyscallType
from nitro.backends.arguments import ArgumentMap, SyscallArgumentType

class WindowsArgumentMap(ArgumentMap):

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
        "arg_size_format",
    )
    
    def __init__(self, event, name, process, nitro):
        super().__init__(event, name, process, nitro)
        self.arg_size_format = self.ARG_SIZE[self.event.type]

    def __getitem__(self, index):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError as error:
            raise RuntimeError('Unknown covention') from error
        except IndexError:
            arg_type, opaque = self.CONVENTION[self.event.type][-1]
            opaque += index - len(self.CONVENTION[self.event.type]) + 1
        if arg_type == SyscallArgumentType.register:
            value = self.event.get_register(opaque)
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            addr = self.event.regs.rsp + (opaque * size)
            value, *rest = struct.unpack(self.arg_size_format, self.process.read_memory(addr, size))
        return value

    def __setitem__(self, index, value):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError as error:
            raise RuntimeError('Unknown covention') from error
        except IndexError:
            arg_type, opaque = self.CONVENTION[self.event.type][-1]
            opaque += index - len(self.CONVENTION[self.event.type]) + 1
        if arg_type == SyscallArgumentType.register:
            self.event.update_register(opaque, value)
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            addr = self.event.regs.rsp + (opaque * size)
            buffer = struct.pack(self.arg_size_format, value)
            self.process.write_memory(addr, buffer)
        self.modified[index] = value

