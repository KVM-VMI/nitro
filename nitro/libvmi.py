import logging
from enum import Enum


from nitro.build_libvmi import ffi, lib

# cffi 0.8.6 doesn't parse # define
# we have to put these constants here
VMI_INIT_DOMAINNAME = 1
VMI_INIT_DOMAINID = 2
VMI_INIT_EVENTS = 4
VMI_INIT_SHM = 8

VMI_SUCCESS = 0
VMI_FAILURE = 1

class LibvmiError(Exception):
    pass

class VMIOS(Enum):
    UNKNOWN = 0
    LINUX = 1
    WINDOWS = 2


class Libvmi:

    __slots__ = (
        'opaque_vmi',
        'vmi',
        'libvmi',
        'stats',
        'failures'
    )

    def __init__(self, vm_name):
        self.opaque_vmi = ffi.new("vmi_instance_t *")
        init_error = ffi.new("vmi_init_error_t *")

        # init libvmi
        status = lib.vmi_init_complete(self.opaque_vmi,
                                       vm_name.encode(),
                                       VMI_INIT_DOMAINNAME,
                                       ffi.NULL,
                                       lib.VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                       ffi.NULL,
                                       init_error)
        if status != VMI_SUCCESS:
            # TODO extract error value and log it
            raise LibvmiError('VMI_FAILURE')
        # store handle to real vmi_instance_t
        self.vmi = self.opaque_vmi[0]

    def destroy(self):
        status = lib.vmi_destroy(self.vmi)
        if status != VMI_SUCCESS:
            raise LibvmiError('VMI_FAILURE')
        self.vmi = None

    def translate_ksym2v(self, symbol):
        addr = ffi.new("addr_t *")
        status = lib.vmi_translate_ksym2v(self.vmi, symbol.encode(), addr)
        if status != VMI_SUCCESS:
            raise LibvmiError('VMI_FAILURE')
        return addr[0]

    def translate_v2ksym(self, vaddr):
        ctx = ffi.new("access_context_t *")
        ctx.translate_mechanism = lib.VMI_TM_PROCESS_PID
        str = lib.vmi_translate_v2ksym(self.vmi, ctx, vaddr)
        return ffi.string(str).decode()

    def translate_kv2p(self, vaddr):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_translate_kv2p(self.vmi, vaddr, paddr)
        if status != VMI_SUCCESS:
            raise LibvmiError('VMI_FAILURE')
        return paddr[0]

    def read_addr_ksym(self, symbol):
        addr = ffi.new("addr_t *")
        status = lib.vmi_read_addr_ksym(self.vmi, symbol.encode(), addr)
        if status != VMI_SUCCESS:
            logging.debug('VMI_FAILURE trying to read %s, with %s', symbol, 'read_addr_ksym')
            raise LibvmiError('VMI_FAILURE')
        return addr[0]

    def get_offset(self, offset_name):
        offset = ffi.new("addr_t *")
        status = lib.vmi_get_offset(self.vmi, offset_name.encode(), offset)
        if status !=  VMI_SUCCESS:
            raise LibvmiError('VMI_FAILURE')
        return offset[0]

    def get_ostype(self):
        os = lib.vmi_get_ostype(self.vmi)
        return VMIOS(os)

    def read_addr_va(self, vaddr, pid):
        if vaddr == 0:
            raise ValueError('Nullptr')
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_va(self.vmi, vaddr, pid, value)
        if status != VMI_SUCCESS:
            logging.debug('VMI_FAILURE trying to read %s, with %s', hex(vaddr), 'read_addr_va')
            raise LibvmiError('VMI_FAILURE')
        return value[0]

    def read_str_va(self, vaddr, pid):
        if vaddr == 0:
            raise ValueError('Nullptr')
        str = lib.vmi_read_str_va(self.vmi, vaddr, pid)
        return ffi.string(str).decode()

    def read_va(self, vaddr, pid, count):
        if vaddr == 0:
            raise ValueError('Nullptr')
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_va(self.vmi, vaddr, pid, count, buffer, bytes_read)
        if status != VMI_SUCCESS or bytes_read[0] != count:
            logging.debug('VMI_FAILURE trying to read %s, with %s', hex(vaddr), 'read_va')
            raise LibvmiError('VMI_FAILURE')
        return ffi.buffer(buffer, bytes_read[0])[:]

    def write_va(self, vaddr, pid, buffer):
        if vaddr == 0:
            raise ValueError('Nullptr')
        buffer_c = ffi.frombuffer(buffer)
        bytes_written = ffi.new("size_t *")
        status = lib.vmi_write_va(self.vmi, vaddr, pid, len(buffer), buffer_c, bytes_written)
        if status != VMI_SUCCESS or bytes_written != len(buffer):
            logging.debug('VMI_FAILURE trying to write %s, with %s', hex(vaddr), 'write_va')
            raise LibvmiError('VMI_FAILURE')

    def read_32(self, vaddr, pid):
        ctx = ffi.new("access_context_t *")
        ctx.translate_mechanism = lib.VMI_TM_PROCESS_PID
        ctx.addr = vaddr
        ctx.pid = pid
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32(self.vmi, ctx, value)
        if status != VMI_SUCCESS:
            logging.debug('VMI_FAILURE trying to read_32 at %s with pid %s',
                          hex(vaddr), pid)
            raise LibvmiError('VMI_FAILURE')
        return value[0]

    def v2pcache_flush(self, dtb=0):
        lib.vmi_v2pcache_flush(self.vmi, dtb)

    def pidcache_flush(self):
        lib.vmi_pidcache_flush(self.vmi)

    def symcache_flush(self):
        lib.vmi_symcache_flush(self.vmi)

    def rvacache_flush(self):
        lib.vmi_rvacache_flush(self.vmi)
