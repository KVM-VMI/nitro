import datetime
from nitro.backends.process import Process
from nitro.backends.windows.types import PEB, UnicodeString, LargeInteger

WINDOWS_TICK = 10000000
SEC_TO_UNIX_EPOCH = 11644473600

class WindowsProcess(Process):

    __slots__ = (
        "eproc",
        "name",
        "pid",
        "iswow64",
        "create_time",
        "path",
        "command_line",
        "parent_pid",
        "symbols"
    )

    def __init__(self, libvmi, cr3, eproc, symbols):
        super().__init__(libvmi, cr3)
        self.eproc = eproc
        self.symbols = symbols

        # get name
        image_file_name_off = self.eproc + self.symbols['offsets']['EPROCESS']['ImageFileName']
        self.name = self.libvmi.read_str_va(image_file_name_off, 0)
        # get pid
        unique_processid_off = self.eproc + self.symbols['offsets']['EPROCESS']['UniqueProcessId']
        self.pid = self.libvmi.read_addr_va(unique_processid_off, 0)
        # get command line
        peb_addr = self.libvmi.read_addr_va(self.eproc + self.symbols['offsets']['EPROCESS']['Peb'], 0)
        peb = PEB(peb_addr, self)
        self.command_line = peb.ProcessParameters.CommandLine.Buffer
        # get full path
        seauditprocesscreationinfo_offs = self.eproc + self.symbols['offsets']['EPROCESS']['SeAuditProcessCreationInfo']
        sapci = self.libvmi.read_addr_va(seauditprocesscreationinfo_offs, 0)
        fullpath = UnicodeString(sapci, self)
        self.path = fullpath.Buffer
        # get create time
        create_time = self.eproc + self.symbols['offsets']['EPROCESS']['CreateTime']
        ct = LargeInteger(create_time, self)
        # Converts Windows 64-bit time to UNIX time, the below code has been taken from Volatility
        ct = ct.QuadPart / WINDOWS_TICK
        ct = ct - SEC_TO_UNIX_EPOCH
        self.create_time = datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
        # get parent PID
        parent_pid_offs = self.eproc + self.symbols['offsets']['EPROCESS']['InheritedFromUniqueProcessId']
        ppid = self.libvmi.read_addr_va(parent_pid_offs, 0)
        self.parent_pid = ppid
        # get iswow64, if value is non-zero then iswow64 is true
        self.iswow64 = self.libvmi.read_addr_va(self.eproc + self.symbols['offsets']['EPROCESS']['Wow64Process'], 0) != 0
    
    def as_dict(self):
        parent = super().as_dict()
        parent["parent_pid"] = self.parent_pid
        parent["command_line"] = self.command_line
        parent["iswow64"] = self.iswow64
        parent["path"] = self.path
        parent["create_time"] = self.create_time
        return parent

