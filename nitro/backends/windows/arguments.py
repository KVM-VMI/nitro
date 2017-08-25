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

    def __getitem__(self, index):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError as error:
            raise RuntimeError('Unknown convention') from error
        except IndexError:
            arg_type, opaque = self.CONVENTION[self.event.type][-1]
            opaque += index - len(self.CONVENTION[self.event.type]) + 1

        return self.get_argument_value(arg_type, opaque)

    def __setitem__(self, index, value):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError as error:
            raise RuntimeError('Unknown covention') from error
        except IndexError:
            arg_type, opaque = self.CONVENTION[self.event.type][-1]
            opaque += index - len(self.CONVENTION[self.event.type]) + 1

        self.set_argument_value(arg_type, opaque, value)
        self.modified[index] = value
