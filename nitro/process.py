class Process:

    def __init__(self, cr3, start_eproc, name, pid, libvmi):
        self.cr3 = cr3
        self.start_eproc = start_eproc
        self.name = name
        self.pid = pid
        self.libvmi = libvmi

    def info(self):
        info = {}
        info['name'] = self.name
        info['pid'] = self.pid
        return info

    def read_memory(self, addr, count):
        return self.libvmi.read_va(addr, self.pid, count)

    def write_memory(self, addr, buffer):
        return self.libvmi.write_va(addr, self.pid, buffer)