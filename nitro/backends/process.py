class Process:

    __slots__ = (
        "libvmi",
        "cr3",
        "descriptor",
    )

    def __init__(self, libvmi, cr3, descriptor):
        self.libvmi = libvmi
        self.cr3 = cr3
        self.descriptor = descriptor

    def as_dict(self):
        info = {
            'name': self.name,
            'pid': self.pid
        }
        return info

    def read_memory(self, addr, count):
        return self.libvmi.read_va(addr, self.pid, count)

    def write_memory(self, addr, buffer):
        return self.libvmi.write_va(addr, self.pid, buffer)
