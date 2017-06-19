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
        "modified"
    )

    def __init__(self, event, name, process):
        self.event = event
        self.name = name
        self.process = process
        self.modified = {}
