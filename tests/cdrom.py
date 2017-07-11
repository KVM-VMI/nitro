import os
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
        # write autorun.inf
        self.write_autorun()
        # write main script
        self.write_run_bat()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()

    def cleanup(self):
        if self.cdrom_iso_tmp:
            self.cdrom_iso_tmp.close()
        self.tmp_dir.cleanup()
        self.cdrom_dir_tmp.cleanup()

    def write_autorun(self):
        # write autorun.inf
        content = """
[autorun]
open=run.bat
"""[1:].replace('\n', '\r\n')
        autorun_path = os.path.join(self.cdrom_dir, 'autorun.inf')
        with open(autorun_path, 'w') as f:
            f.write(content)

    def write_run_bat(self):
        # write autorun.inf
        content = """
CALL test.bat
sc stop winrm
"""[1:].replace('\n', '\r\n')
        run_bat_path = os.path.join(self.cdrom_dir, 'run.bat')
        with open(run_bat_path, 'w') as f:
            f.write(content)

    def set_script(self, script, powershell=False):
        script = script.replace('\n', '\r\n')
        if powershell:
            test_bat_content = 'powershell -File test.ps1'
            # write test.ps1
            test_ps1_path = os.path.join(self.cdrom_dir, 'test.ps1')
            with open(test_ps1_path, 'w') as f:
                f.write(script)
        else:
            test_bat_content = script
        test_bat_path = os.path.join(self.cdrom_dir, 'test.bat')
        with open(test_bat_path, 'w') as f:
            f.write(test_bat_content)

    def set_executable(self, exe_path):
        exe_path = Path(exe_path)
        # copy executable
        exe_path_cdrom = os.path.join(self.cdrom_dir, exe_path.name)
        shutil.copyfile(str(exe_path), exe_path_cdrom)
        # write test.bat
        content = """
{}
""".format(exe_path.name)[1:].replace('\n', '\r\n')
        test_bat_path = os.path.join(self.cdrom_dir, 'test.bat')
        with open(test_bat_path, 'w') as f:
            f.write(content)

    def generate_iso(self, cleanup=True):
        self.cdrom_iso_tmp = NamedTemporaryFile(delete=False, dir=self.tmp_dir.name)
        cdrom_iso = self.cdrom_iso_tmp.name
        # chmod to be r/w by everyone
        # so we can remove the file even when qemu takes the ownership

        # generate iso
        genisoimage_bin = shutil.which('genisoimage')
        if genisoimage_bin is None:
            raise Exception('Cannot find genisoimage executable')
        args = [genisoimage_bin, '-o', cdrom_iso, '-iso-level', '4', self.cdrom_dir]
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.debug('ISO generated at {}'.format(cdrom_iso))
        # cleanup
        if cleanup:
            self.cdrom_dir_tmp.cleanup()
        return cdrom_iso

