import logging
import struct


class WinStruct(object):

    _fields_ = []

    def __init__(self, addr, pid, vmi):
        logging.debug('Building {} from {}'.format(self.__class__.__name__, hex(addr)))
        self.addr = addr
        self.pid = pid
        self.vmi = vmi
        offset = 0
        for f_name, f_format in self._fields_:
            logging.debug('Field {}, {}'.format(f_name, f_format))
            if f_format == 'P':
                f_format = 'II'
                f_size = struct.calcsize(f_format)
                content = self.vmi.read_va(addr + offset, self.pid, f_size)
                *rest, f_value = struct.unpack(f_format, content)
            else:
                f_size = struct.calcsize(f_format)
                content = self.vmi.read_va(addr + offset, self.pid, f_size)
                f_value, *rest = struct.unpack(f_format, content)
            logging.debug('Value: {}'.format(hex(f_value)))
            setattr(self, f_name, f_value)
            offset += f_size


class ObjectAttributes(WinStruct):

    _fields_ = [
            ('Length', 'I'),
            ('Handle', 'P'),
            ('PUnicodeString', 'P'),
            ]

    def __init__(self, addr, pid, vmi):
        super(ObjectAttributes, self).__init__(addr, pid, vmi)
        self.PUnicodeString = UnicodeString(self.PUnicodeString, pid, vmi)


class UnicodeString(WinStruct):

    _fields_ = [
            ('Length', 'H'),
            ('MaximumLength', 'H'),
            ('Buffer', 'P'),
            ]

    def __init__(self, addr, pid, vmi):
        super(UnicodeString, self).__init__(addr, pid, vmi)
        buffer = self.vmi.read_va(self.Buffer, pid, self.Length)
        try:
            string = buffer.decode('utf-16-le')
        except UnicodeDecodeError:
            string = "UnicodeDecodeError"
        self.Buffer = string
