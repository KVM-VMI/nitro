import logging
from enum import Enum
from ctypes import *

charptr = POINTER(c_char)

VMI_SUCCESS = 0
VMI_FAILURE = 1

VMI_INIT_DOMAINNAME = (1 << 0)  # initialize using domain name

VMI_INIT_DOMAINID = (1 << 1) # initialize using domain id


class VMIMode(Enum):
    VMI_XEN = 0
    VMI_KVM = 1
    VMI_FILE = 2


class VMIConfig(Enum):
    VMI_CONFIG_GLOBAL_FILE_ENTRY = 0
    VMI_CONFIG_STRING = 1
    VMI_CONFIG_GHASHTABLE = 2


class LibvmiError(Exception):
    pass


class VMIInstance(Structure):
    _fields_ = [("buffer", c_int * 1024 * 1024 * 10)]


class Libvmi:

    __slots__ = (
        'libvmi',
        'vmi_instance',
        'vmi',
        'sdt',
        'libvmi',
        'processes',
        'hooks',
        'stats',
    )

    def __init__(self, vm_name):
        self.libvmi = cdll.LoadLibrary('libvmi.so')
        self.vmi_instance = VMIInstance()
        self.vmi = pointer(self.vmi_instance)
        # init libvmi
        vm_name_c = create_string_buffer(vm_name.encode('utf-8'))
        self.libvmi.vmi_init_complete(byref(self.vmi), vm_name_c, VMI_INIT_DOMAINNAME, 0,
                                      VMIConfig.VMI_CONFIG_GLOBAL_FILE_ENTRY.value, 0, 0)
        # small fixes
        self.libvmi.vmi_translate_ksym2v.restype = c_ulonglong
        self.libvmi.vmi_get_offset.restype = c_ulonglong
        self.libvmi.vmi_read_str_va.restype = charptr

    def destroy(self):
        self.libvmi.vmi_destroy(self.vmi)

    def translate_ksym2v(self, symbol):
        symbol_c = create_string_buffer(symbol.encode('utf-8'))
        value = self.libvmi.vmi_translate_ksym2v(self.vmi, symbol_c)
        return value

    def read_addr_ksym(self, symbol):
        symbol_c = create_string_buffer(symbol.encode('utf-8'))
        value_c = c_ulonglong()
        status = self.libvmi.vmi_read_addr_ksym(self.vmi, symbol_c, byref(value_c))
        if status == VMI_FAILURE:
            logging.debug('VMI_FAILURE trying to read {}, with {}'.format(symbol, 'read_addr_ksym'))
            raise LibvmiError('VMI_FAILURE')

        return value_c.value

    def get_offset(self, offset):
        offset_name_c = create_string_buffer(offset.encode('utf-8'))
        value = self.libvmi.vmi_get_offset(self.vmi, offset_name_c)
        return value

    def read_addr_va(self, vaddr, pid):
        if vaddr == 0:
            raise ValueError('Nullptr')
        vaddr_c = c_ulonglong(vaddr)
        pid_c = c_int(pid)
        value_c = c_ulonglong()
        status = self.libvmi.vmi_read_addr_va(self.vmi, vaddr_c, pid_c, byref(value_c))
        if status == VMI_FAILURE:
            logging.debug('VMI_FAILURE trying to read {}, with {}'.format(hex(vaddr), 'read_addr_va'))
            raise LibvmiError('VMI_FAILURE')
        return value_c.value

    def read_str_va(self, vaddr, pid):
        if vaddr == 0:
            raise ValueError('Nullptr')
        vaddr_c = c_ulonglong(vaddr)
        pid_c = c_int(pid)
        ptr = self.libvmi.vmi_read_str_va(self.vmi, vaddr_c, pid_c)
        string = cast(ptr, c_char_p).value.decode('utf-8')
        return string

    def read_va(self, vaddr, pid, count):
        if vaddr == 0:
            raise ValueError('Nullptr')
        vaddr_c = c_ulonglong(vaddr)
        pid_c = c_int(pid)
        buffer = (c_char * count)()
        nb_read = self.libvmi.vmi_read_va(self.vmi, vaddr_c, pid_c, byref(buffer), count)
        if nb_read == 0:
            logging.debug('VMI_FAILURE trying to read {}, with {}'.format(hex(vaddr), 'read_va'))
            raise LibvmiError('VMI_FAILURE')
        value = bytes(buffer)[:nb_read]
        return value

    def v2pcache_flush(self, dtb=0):
        self.libvmi.vmi_v2pcache_flush(self.vmi, dtb)

    def pidcache_flush(self):
        self.libvmi.vmi_pidcache_flush(self.vmi)

    def symcache_flush(self):
        self.libvmi.vmi_symcache_flush(self.vmi)

    def rvacache_flush(self):
        self.libvmi.vmi_rvacache_flush(self.vmi)

    def pagecache_flush(self):
        self.libvmi.vmi_pagecache_flush(self.vmi)
