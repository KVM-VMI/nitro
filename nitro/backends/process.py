
class Process:
    """
    Base class for processes. ``Process`` provides accesss to information about a
    particular process as well as a method for reading and writing its memory.
    """

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
        """
        Returns a dictionary representing the process.

        :rtype: dict
        """
        return {
            'name': self.name,
            'pid': self.pid
        }

    def read_memory(self, addr, count):
        """
        Read ``count`` bytes at address ``addr`` from the process' address space.
        
        :raises: LibvmiError
        """
        return self.libvmi.read_va(addr, self.pid, count)

    def write_memory(self, addr, buffer):
        """
        Write ``buffer`` at address ``addr`` in the process' address space.

        :raises: LibvmiError
        """
        return self.libvmi.write_va(addr, self.pid, buffer)
