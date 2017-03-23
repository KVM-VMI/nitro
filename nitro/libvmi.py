import logging
from ctypes import *

charptr = POINTER(c_char)

VMI_SUCCESS = 0
VMI_FAILURE = 1

VMI_AUTO = (1 << 0)

VMI_XEN = (1 << 1)

VMI_KVM = (1 << 2)

VMI_FILE = (1 << 3)

VMI_INIT_PARTIAL = (1 << 16)

VMI_INIT_COMPLETE = (1 << 17)

#define VMI_INIT_EVENTS (1 << 18) /**< init support for VM events */

#define VMI_INIT_SHM_SNAPSHOT (1 << 19) /**< setup shm-snapshot in vmi_init() if the feature is activated */

#define VMI_CONFIG_NONE (1 << 24) /**< no config provided */

#define VMI_CONFIG_GLOBAL_FILE_ENTRY (1 << 25) /**< config in file provided */

#define VMI_CONFIG_STRING (1 << 26) /**< config string provided */

#define VMI_CONFIG_GHASHTABLE (1 << 27) /**< config GHashTable provided */

#define VMI_INVALID_DOMID ~0ULL /**< invalid domain id */




class VMIInstance(Structure):
    _fields_ = [("buffer", c_int * 1024 * 1024 * 10)]


class Libvmi:

    def __init__(self, vm_name):
        self.libvmi = cdll.LoadLibrary('libvmi.so')
        self.vmi_instance = VMIInstance()
        self.vmi = pointer(self.vmi_instance)
        # init libvmi
        vm_name_c = create_string_buffer(vm_name.encode('utf-8'))
        self.libvmi.vmi_init(byref(self.vmi), VMI_KVM | VMI_INIT_COMPLETE, vm_name_c)
        # small fixes
        self.libvmi.vmi_translate_ksym2v.restype = c_ulonglong
        self.libvmi.vmi_get_offset.restype = c_ulonglong
        self.libvmi.vmi_read_str_va.restype = charptr
        self.failures = 0

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
            self.failures += 1
            logging.debug('VMI_FAILURE trying to read {}, with {}'.format(symbol, 'read_addr_ksym'))
            raise ValueError('VMI_FAILURE')

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
            self.failures += 1
            logging.debug('VMI_FAILURE trying to read {}, with {}'.format(hex(vaddr), 'read_addr_va'))
            raise ValueError('VMI_FAILURE')
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
            self.failures += 1
            logging.debug('VMI_FAILURE trying to read {}, with {}'.format(hex(vaddr), 'read_va'))
            raise ValueError('VMI_FAILURE')
        value = bytes(buffer)[:nb_read]
        return value
