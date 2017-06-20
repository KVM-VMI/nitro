import struct

from enum import Enum
from nitro.event import SyscallType

class SyscallArgumentType(Enum):
    register = 0
    memory = 1


class ArgumentMap:

    ARG_SIZE = {
        SyscallType.syscall: 'P',   # x64 -> 8 bytes
        SyscallType.sysenter: 'I'   # x32 -> 4 bytes
    }

    __slots__ = (
        "event",
        "name",
        "process",
        "modified",
        "arg_size_format"
    )

    def __init__(self, event, name, process):
        self.event = event
        self.name = name
        self.process = process
        self.modified = {}
        self.arg_size_format = self.ARG_SIZE[self.event.type]

    def get_argument_value(self, arg_type, opaque):
        if arg_type == SyscallArgumentType.register:
            value = self.event.get_register(opaque)
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            addr = self.event.regs.rsp + (opaque * size)
            value, *rest = struct.unpack(self.arg_size_format, self.process.read_memory(addr, size))
        return value

    def set_argument_value(self, arg_type, opaque, value):
        if arg_type == SyscallArgumentType.register:
            self.event.update_register(opaque, value)
        else:
            # memory
            size = struct.calcsize(self.arg_size_format)
            addr = self.event.regs.rsp + (opaque * size)
            buffer = struct.pack(self.arg_size_format, value)
            self.process.write_memory(addr, buffer)
