import logging
import struct
from  array import array

class WinStruct(object):

    _fields_ = []

    def __init__(self, addr, ctxt, vmi):
        logging.debug('Building {} from {}'.format(self.__class__.__name__, hex(addr)))
        self.addr = addr
        self.ctxt = ctxt
        self.vmi = vmi
        offset = 0
        for f_name, f_format in self._fields_:
            logging.debug('Field {}, {}'.format(f_name, f_format))
            f_size = struct.calcsize(f_format)
            import ipdb; ipdb.set_trace()
            content = self.vmi.read_va(addr + offset, self.ctxt.process.pid, f_size)
            ar = array('B', content)
            logging.debug(ar)
            f_value = struct.unpack(f_format, ar.tostring())[0]
            logging.debug('Value: {}'.format(hex(f_value)))
            setattr(self, f_name, f_value)
            offset += f_size

class ObjectAttributes(WinStruct):

    _fields_ = [
            ('Length', 'I'),
            ('Handle', 'P'),
            ('PUnicodeString', '<Q'),
            ]

    def __init__(self, addr, ctxt, vmi):
        logging.debug('here')
        super(ObjectAttributes, self).__init__(addr, ctxt, vmi)
        self.PUnicodeString = UnicodeString(self.PUnicodeString, ctxt, vmi)


class UnicodeString(WinStruct):

    _fields_ = [
            ('Length', 'H'),
            ('MaximumLength', 'H'),
            ('Buffer', 'P'),
            ]

    def __init__(self, addr, ctxt, vmi):
        super(UnicodeString, self).__init__(addr, ctxt, vmi)
        content = self.vmi.read_va(self.Buffer, self.ctxt.process.pid, self.Length)
        try:
            string = unicode(content, 'utf-16-le')
        except UnicodeDecodeError:
            string = "UnicodeDecodeError"
            self.Buffer = string
        else:
            self.Buffer = string
