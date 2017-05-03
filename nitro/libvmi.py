import logging
from enum import Enum
from ctypes import *
from enum import Enum

charptr = POINTER(c_char)

# status_t

VMI_SUCCESS = 0
VMI_FAILURE = 1

class LibvmiInitError(Enum):
    NONE = 0                 #No error
    DRIVER_NOT_DETECTED = 1  # Failed to auto-detect hypervisor
    DRIVER = 2               # Failed to initialize hypervisor-driver
    VM_NOT_FOUND = 3         # Failed to find the specified VM
    PAGING = 4               # Failed to determine or initialize paging functions
    OS = 5                   # Failed to determine or initialize OS functions
    EVENTS = 6               # Failed to initialize events
    SHM = 7                  # Failed to initialize SHM
    NO_CONFIG = 8            # No configuration was found for OS initialization
    NO_CONFIG_ENTRY = 9      # Configuration contained no valid entry for VM

# VMI_INIT

VMI_INIT_DOMAINNAME = (1 << 0)
VMI_INIT_DOMAINID = (1 << 1)
VMI_INIT_EVENT = (1 << 2)
VMI_INIT_SHM = (1 << 3)

# os_t

class VMIOS(Enum):
    UNKNOWN = 0
    LINUX = 1
    WINDOWS = 2

# vmi_mode_t

class VMIMode(Enum):
    XEN = 0
    KVM = 1
    FILE = 2

# vmi_config_t

class VMIConfig(Enum):
    GLOBAL_FILE_ENTRY = 0
    STRING = 1
    GHASHTABLE = 2

# translation_mechanisms_t

class TranslationMechanism(Enum):
    INVALID = 0
    NONE = 1
    PROCESS_DTB = 2
    PROCESS_PID = 3
    KERNEL_SYMBOL = 4

# access_context_t

class AccessContext(Structure):
    _fields_ = [
        ("translation_mechanism", c_int),
        ("addr", c_uint64),
        ("ksym", charptr),
        ("dtb", c_uint64),
        ("pid", c_int32)
    ]

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
        'failures'
    )

    def __init__(self, vm_name):
        self.libvmi = cdll.LoadLibrary('libvmi.so')
        self.vmi_instance = VMIInstance()
        self.vmi = pointer(self.vmi_instance)
        init_error_c = c_uint()
        # init libvmi
        vm_name_c = create_string_buffer(vm_name.encode('utf-8'))
        status = self.libvmi.vmi_init_complete(byref(self.vmi), vm_name_c, VMI_INIT_DOMAINNAME, 0,
                                      VMIConfig.GLOBAL_FILE_ENTRY.value, 0, byref(init_error_c))
        if status == VMI_FAILURE:
            error = init_error_c.value
            logging.error(format(LibvmiInitError(error).name))
            raise LibvmiError('VMI_FAILURE')
        # small fixes
        self.libvmi.vmi_translate_ksym2v.restype = c_ulonglong
        self.libvmi.vmi_get_offset.restype = c_ulonglong
        self.libvmi.vmi_read_str_va.restype = charptr
        self.libvmi.vmi_translate_v2ksym.restype = charptr
        self.failures = 0

    def destroy(self):
        self.libvmi.vmi_destroy(self.vmi)

    def translate_ksym2v(self, symbol):
        symbol_c = create_string_buffer(symbol.encode('utf-8'))
        value = self.libvmi.vmi_translate_ksym2v(self.vmi, symbol_c)
        return value

    def translate_v2ksym(self, vaddr):
        context = AccessContext(TranslationMechanism.PROCESS_PID.value, 0, None, 0, 0)
        vaddr = c_uint64(vaddr)
        ptr = self.libvmi.vmi_translate_v2ksym(self.vmi, byref(context), vaddr)
        if ptr:
            return cast(ptr, c_char_p).value.decode('utf-8')
        else:
            logging.debug("Failed to find symbol associated with virtual address: {}".format(vaddr))

    def translate_kv2p(self, vaddr):
        return self.libvmi.vmi_translate_kv2p(self.vmi, c_uint64(vaddr))

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

    def get_ostype(self):
        return VMIOS(self.libvmi.vmi_get_ostype(self.vmi))

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

    def write_va(self, vaddr, pid, buffer):
        if vaddr == 0:
            raise ValueError('Nullptr')
        vaddr_c = c_ulonglong(vaddr)
        pid_c = c_int(pid)
        count = len(buffer)
        count_c = c_int(count)
        buffer_c = create_string_buffer(buffer)
        nb_written = self.libvmi.vmi_write_va(self.vmi, vaddr_c, pid_c, buffer_c, count_c)
        if nb_written == 0 or nb_written != count:
            logging.debug('VMI_FAILURE trying to write {}, with {}'.format(hex(vaddr), 'write_va'))
            raise LibvmiError('VMI_FAILURE')
        return nb_written

    def read_32(self, vaddr, pid):
        context = AccessContext(TranslationMechanism.PROCESS_PID.value, c_uint64(vaddr), None, 0, c_int32(pid))
        result = c_uint32()
        if self.libvmi.vmi_read_32(self.vmi, byref(context), byref(result)) == VMI_SUCCESS:
            return result.value
        else:
            self.failures += 1
            logging.debug('VMI_FAILURE trying to read_32 at 0x{:x} with pid {}'.format(vaddr, pid))
            raise LibvmiError('VMI_FAILURE')

    def v2pcache_flush(self, dtb=0):
        self.libvmi.vmi_v2pcache_flush(self.vmi, dtb)

    def pidcache_flush(self):
        self.libvmi.vmi_pidcache_flush(self.vmi)

    def symcache_flush(self):
        self.libvmi.vmi_symcache_flush(self.vmi)

    def rvacache_flush(self):
        self.libvmi.vmi_rvacache_flush(self.vmi)

    # def pagecache_flush(self):
    #     self.libvmi.vmi_pagecache_flush(self.vmi)
