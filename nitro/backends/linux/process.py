from nitro.backends.process import Process

class LinuxProcess(Process):
    __slots__ = (
        "task_struct",
        "name",
        "pid"
    )

    def __init__(self, libvmi, cr3, task_struct):
        super().__init__(libvmi, cr3)
        pid_offset = self.libvmi.get_offset("linux_pid")
        name_offset = self.libvmi.get_offset("linux_name")

        self.task_struct = task_struct
        self.pid = self.libvmi.read_32(self.task_struct + pid_offset, 0)
        self.name = self.libvmi.read_str_va(self.task_struct + name_offset, 0)
