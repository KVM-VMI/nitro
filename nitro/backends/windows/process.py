from nitro.backends.process import Process

class WindowsProcess(Process):

    __slots__ = (
        "eproc",
        "name",
        "pid"
    )

    def __init__(self, libvmi, cr3, eproc):
        super().__init__(libvmi, cr3)
        self.eproc = eproc
        # get name
        image_file_name_off = self.eproc + self.libvmi.get_offset('win_pname')
        self.name = self.libvmi.read_str_va(image_file_name_off, 0)
        # get pid
        unique_processid_off = self.eproc + self.libvmi.get_offset('win_pid')
        self.pid = self.libvmi.read_addr_va(unique_processid_off, 0)
