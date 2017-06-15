from enum import Enum


class SyscallArgumentType(Enum):
    register = 0
    memory = 1


class ArgumentMap:
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
