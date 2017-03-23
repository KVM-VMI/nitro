import logging
import struct


class WinStruct(object):

    _fields_ = []

    def __init__(self, addr, pid, vmi):
        # logging.debug('Building {} from {}'.format(self.__class__.__name__, hex(addr)))
        self.addr = addr
        self.pid = pid
        self.vmi = vmi
        for f_offset, f_name, f_format in self._fields_:
            # logging.debug('Field {}, {}, at {} + {}'.format(f_name, f_format, hex(addr), hex(f_offset)))
            f_size = struct.calcsize(f_format)
            content = self.vmi.read_va(addr + f_offset, self.pid, f_size)
            f_value, *rest = struct.unpack(f_format, content)
            # logging.debug('Value: {}'.format(hex(f_value)))
            setattr(self, f_name, f_value)


class ObjectAttributes(WinStruct):

    _fields_ = [
            (0, 'Length',  'I'),
            (0x8, 'Handle', 'P'),
            (0x10, 'PUnicodeString', 'P'),
            ]

    def __init__(self, addr, pid, vmi):
        super(ObjectAttributes, self).__init__(addr, pid, vmi)
        self.PUnicodeString = UnicodeString(self.PUnicodeString, pid, vmi)


class UnicodeString(WinStruct):

    _fields_ = [
            (0, 'Length', 'H'),
            (0x2, 'MaximumLength', 'H'),
            (0x8, 'Buffer', 'P'),
            ]

    def __init__(self, addr, pid, vmi):
        super(UnicodeString, self).__init__(addr, pid, vmi)
        buffer = self.vmi.read_va(self.Buffer, pid, self.Length)
        try:
            string = buffer.decode('utf-16-le')
        except UnicodeDecodeError:
            string = "UnicodeDecodeError"
        self.Buffer = string
