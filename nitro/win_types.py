import logging
import struct


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

    _fields_ = [
            (0, 'Length',  'I'),
            (0x8, 'Handle', 'P'),
            (0x10, 'PUnicodeString', 'P'),
            ]

    def __init__(self, addr, process):
        super(ObjectAttributes, self).__init__(addr, process)
        self.PUnicodeString = UnicodeString(self.PUnicodeString, process)


class UnicodeString(WinStruct):

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
            string = "UnicodeDecodeError"
        self.Buffer = string
