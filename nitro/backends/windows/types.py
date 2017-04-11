import logging
import struct

class InconsistentMemoryError(Exception):
    pass

class WinStruct(object):

    _fields_ = []

    def __init__(self, addr, process):
        # logging.debug('Building {} from {}'.format(self.__class__.__name__, hex(addr)))
        for f_offset, f_name, f_format in self._fields_:
            # logging.debug('Field {}, {}, at {} + {}'.format(f_name, f_format, hex(addr), hex(f_offset)))
            f_size = struct.calcsize(f_format)
            content = process.read_memory(addr + f_offset, f_size)
            f_value, *rest = struct.unpack(f_format, content)
            # logging.debug('Value: {}'.format(hex(f_value)))
            setattr(self, f_name, f_value)


class ObjectAttributes(WinStruct):

    __slots__ = (
        'Length',
        'RootDirectory',
        'ObjectName',
    )

    _fields_ = [
            (0, 'Length',  'I'),
            (0x8, 'RootDirectory', 'P'),
            (0x10, 'ObjectName', 'P'),
            ]

    def __init__(self, addr, process):
        super(ObjectAttributes, self).__init__(addr, process)
        if self.Length != 0x30:
            # memory inconsistent
            raise InconsistentMemoryError()
        self.ObjectName = UnicodeString(self.ObjectName, process)


class UnicodeString(WinStruct):

    __slots__ = (
        'Length',
        'MaximumLength',
        'Buffer',
    )

    _fields_ = [
            (0, 'Length', 'H'),
            (0x2, 'MaximumLength', 'H'),
            (0x8, 'Buffer', 'P'),
            ]

    def __init__(self, addr, process):
        super(UnicodeString, self).__init__(addr, process)
        buffer = process.read_memory(self.Buffer, self.Length)
        try:
            string = buffer.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError('UnicodeDecodeError')
        self.Buffer = string


class AccessMask:

    STANDARD_RIGHTS = [
        (1 << 16, "DELETE"),
        (1 << 17, "READ_CONTROL"),
        (1 << 18, "WRITE_DAC"),
        (1 << 19, "WRITE_OWNER"),
        (1 << 20, "SYNCHRONIZE"),
        (1 << 24, "ACCESS_SYSTEM_SECURITY"),
        (1 << 25, "MAXIMUM_ALLOWED"),
        (1 << 28, "GENERIC_ALL"),
        (1 << 29, "GENERIC_EXECUTE"),
        (1 << 30, "GENERIC_WRITE"),
        (1 << 31, "GENERIC_READ"),
    ]

    def __init__(self, desired_access):
        self.rights = []
        self.rights.extend([right for mask, right in self.STANDARD_RIGHTS if desired_access & mask])


class FileAccessMask(AccessMask):

    SPECIFIC_RIGHTS = [
        (1 << 0, "FILE_READ_DATA"),
        (1 << 1, "FILE_WRITE_DATA"),
        (1 << 2, "FILE_APPEND_DATA"),
        (1 << 3, "FILE_READ_EA"),
        (0x10, "FILE_WRITE_EA"),
        (0x20, "FILE_EXECUTE"),
        (0x80, "FILE_READ_ATTRIBUTES"),
        (0x100, "FILE_WRITE_ATTRIBUTES"),
    ]

    def __init__(self, desired_access):
        super().__init__(desired_access)
        self.rights.extend([right for mask, right in self.SPECIFIC_RIGHTS if desired_access & mask])
