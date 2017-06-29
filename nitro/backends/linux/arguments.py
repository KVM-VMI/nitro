import struct

from nitro.event import SyscallType
from nitro.backends.arguments import ArgumentMap, SyscallArgumentType

class LinuxArgumentMap(ArgumentMap):

    CONVENTION = {
        SyscallType.syscall: [
            (SyscallArgumentType.register, 'rdi'),
            (SyscallArgumentType.register, 'rsi'),
            (SyscallArgumentType.register, 'rdx'),
            (SyscallArgumentType.register, 'r10'),
            (SyscallArgumentType.register, 'r9'),
            (SyscallArgumentType.register, 'r8'),
        ],
        SyscallType.sysenter: [
            (SyscallArgumentType.register, 'rbx'),
            (SyscallArgumentType.register, 'rcx'),
            (SyscallArgumentType.register, 'rdx'),
            (SyscallArgumentType.register, 'rsi'),
            (SyscallArgumentType.register, 'rdi'),
            (SyscallArgumentType.register, 'rbp'),
        ],
    }

    def __getitem__(self, index):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError as error:
            raise RuntimeError('Unknown convention') from error
        except IndexError:
            raise RuntimeError('Invalid argument index: Linux syscalls are '
                               'limited to 6 parameters')

        return self.get_argument_value(arg_type, opaque)


    def __setitem__(self, index, value):
        try:
            arg_type, opaque = self.CONVENTION[self.event.type][index]
        except KeyError as error:
            raise RuntimeError('Unknown convention') from error
        except IndexError:
            raise RuntimeError('Invalid argument index: Linux syscalls are '
                               'limited to 6 parameters')

        self.set_argument_value(arg_type, opaque, value)
        self.modified[index] = value