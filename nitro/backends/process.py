
class Process:

    __slots__ = (
        "libvmi",
        "cr3",
    )

    def __init__(self, libvmi, cr3):
        self.libvmi = libvmi
        self.cr3 = cr3

    @property
    def pid(self):
        raise NotImplementedError("pid must be overridden by a subclass")

    @property
    def name(self):
        raise NotImplementedError("name must be overridden by a subclass")

    def as_dict(self):
        return {
            'name': self.name,
            'pid': self.pid
        }

    def read_memory(self, addr, count):
        return self.libvmi.read_va(addr, self.pid, count)

    def write_memory(self, addr, buffer):
        return self.libvmi.write_va(addr, self.pid, buffer)
