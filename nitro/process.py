from nitro.win_types import PEB, LargeInteger, UnicodeString
import datetime


class Process:

    WINDOWS_TICK = 10000000
    SEC_TO_UNIX_EPOCH = 11644473600

    def __init__(self, cr3, start_eproc, libvmi, symbols):
        self.cr3 = cr3
        self.start_eproc = start_eproc
        self.libvmi = libvmi
        self.symbols = symbols

        # get name
        image_file_name_off = start_eproc + self.symbols['offsets']['EPROCESS']['ImageFileName']
        self.name = self.libvmi.read_str_va(image_file_name_off, 0)
        # get pid
        unique_processid_off = start_eproc + self.symbols['offsets']['EPROCESS']['UniqueProcessId']
        self.pid = self.libvmi.read_addr_va(unique_processid_off, 0)
        # get command line
        peb_addr = self.libvmi.read_addr_va(start_eproc + self.symbols['offsets']['EPROCESS']['Peb'], 0)
        peb = PEB(peb_addr, self)
        self.command_line = peb.ProcessParameters.CommandLine.Buffer
        # get full path
        seauditprocesscreationinfo_offs = start_eproc + self.symbols['offsets']['EPROCESS'][
            'SeAuditProcessCreationInfo']
        sapci = self.libvmi.read_addr_va(seauditprocesscreationinfo_offs, 0)
        fullpath = UnicodeString(sapci, self)
        self.path = fullpath.Buffer
        # get create time
        create_time = start_eproc + self.symbols['offsets']['EPROCESS']['CreateTime']
        ct = LargeInteger(create_time, self)
        # Converts Windows 64-bit time to UNIX time, the below code has been taken from Volatility
        ct = ct.QuadPart / self.WINDOWS_TICK
        ct = ct - self.SEC_TO_UNIX_EPOCH
        self.create_time = datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
        # get parent PID
        parent_pid_offs = start_eproc + self.symbols['offsets']['EPROCESS']['InheritedFromUniqueProcessId']
        ppid = self.libvmi.read_addr_va(parent_pid_offs, 0)
        self.parent_pid = ppid
        # get iswow64, if value is non-zero then iswow64 is true
        self.iswow64 = self.libvmi.read_addr_va(start_eproc + self.symbols['offsets']['EPROCESS']['Wow64Process'],
                                                    0) != 0

    def as_dict(self):
        info = {
            'name': self.name,
            'pid': self.pid,
            'parent_pid': self.parent_pid,
            'command_line': self.command_line,
            'iswow64': self.iswow64,
            'path': self.path,
            'create_time': self.create_time
        }
        return info

    def read_memory(self, addr, count):
        return self.libvmi.read_va(addr, self.pid, count)

    def write_memory(self, addr, buffer):
        return self.libvmi.write_va(addr, self.pid, buffer)
