import os
import textwrap
import stat
import shutil
import logging
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory, NamedTemporaryFile

class CDROM:
    def __init__(self):
        # create cdrom dir
        self.cdrom_dir_tmp = TemporaryDirectory()
        self.tmp_dir = TemporaryDirectory()
        self.cdrom_iso_tmp = None
        # give qemu permission to execute and read in this directory
        os.chmod(self.tmp_dir.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                                    stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
        self.cdrom_dir = self.cdrom_dir_tmp.name
        self.cdrom_iso_tmp = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()

    def cleanup(self):
        if self.cdrom_iso_tmp:
            self.cdrom_iso_tmp.close()
        self.tmp_dir.cleanup()
        self.cdrom_dir_tmp.cleanup()
    
    def add_file_from_str(self, name, content, executable=False, convert_nl=False, dedent=False):
        path = os.path.join(self.cdrom_dir, name)
        if dedent:
            content = textwrap.dedent(content)
        if convert_nl:
            content = content.replace("\n", "\r\n")
        with open(path, "w") as f:
            f.write(content)
        if executable:
            current = os.stat(path)
            os.chmod(path, current.st_mode | stat.S_IEXEC)
    
    def add_file(self, path):
        source = Path(path)
        destination = os.path.join(self.cdrom_dir, source.name)
        shutil.copyfile(str(source), destination)
        shutil.copymode(str(source), destination)

    def generate_iso(self, cleanup=True):
        self.cdrom_iso_tmp = NamedTemporaryFile(delete=False, dir=self.tmp_dir.name)
        cdrom_iso = self.cdrom_iso_tmp.name
        # chmod to be r/w by everyone
        # so we can remove the file even when qemu takes the ownership

        tools = {
            "genisoimage": self.__genisoimage,
            "mkisofs": self.__mkisofs
        }

        available = next(bin for bin in tools.keys() 
                         if shutil.which(bin) is not None)
                
        # generate iso
        if available is None:
            raise Exception('Cannot find tools for creating ISO images')

        tools[available](cdrom_iso)

        logging.debug('ISO generated at %s', cdrom_iso)
        # cleanup
        if cleanup:
            self.cdrom_dir_tmp.cleanup()
        return cdrom_iso

    def __genisoimage(self, cdrom_iso):
        args = ['genisoimage', '-o', cdrom_iso, '-iso-level', '4', '-r', self.cdrom_dir]
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def __mkisofs(self, cdrom_iso):
        args = ['mkisofs', '-o', cdrom_iso, '-iso-level', '4', '-r', self.cdrom_dir]
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class WindowsCDROM(CDROM):
    def __init__(self):
        super().__init__()
        self.write_autorun()
        self.write_run_bat()
    
    def set_executable(self, exe_path):
        exe_path = Path(exe_path)
        self.add_file(exe_path)
        self.add_file_from_str("test.bat", exe_path.name, convert_nl=True)

    def write_autorun(self):
        # write autorun.inf
        content = """
[autorun]
open=run.bat
"""[1:]
        self.add_file_from_str("autorun.inf", content, convert_nl=True)

    def write_run_bat(self):
        content = """
CALL test.bat
sc stop winrm
"""[1:]
        self.add_file_from_str("run.bat", content, convert_nl=True)

    def set_script(self, script, powershell=False):
        script = script.replace('\n', '\r\n')
        if powershell:
            test_bat_content = "powershell -File test.ps1"
            self.add_file_from_str("test.ps1", script, convert_nl=True)
        else:
            test_bat_content = script
        self.add_file_from_str("test.bat", test_bat_content, convert_nl=True)

class LinuxCDROM(CDROM):
    def __init__(self):
        super().__init__()
        self.write_autoexec_sh()
    
    def write_autoexec_sh(self):
        # write autoexec.sh script that executes the supplied test and stops sshd
        content = """
        #!/usr/bin/env bash
        "$(dirname "$(realpath "$0")")/test.sh"
        systemctl stop sshd
        """[1:]
        self.add_file_from_str("autoexec.sh", content, executable=True, dedent=True)

    def set_executable(self, exe_path):
        exe_path = Path(exe_path)
        self.add_file(exe_path)
        bash_script = """
        #!/usr/bin/env bash
        "$(dirname "$(realpath "$0")")/{}"
        """.format(exe_path.name)[1:]
        self.add_file_from_str("test.sh", bash_script, executable=True, dedent=True)

    # It's a bit ugly that these do not share the same signature
    def set_script(self, script, interpreter="/usr/bin/env bash"):
        content = """
        #!{}
        {}
        """.format(interpreter, script)[1:]
        self.add_file_from_str("test.sh", content, dedent=True, executable=True)
