import os.path
import sys
import unittest
import logging
import json
from layers import VMLayer
from vmtest_helper import LinuxVMTestHelper

class TestLinux(unittest.TestCase):
    domain_name = "nitro_ubuntu1604"
    test_helper = LinuxVMTestHelper
    layer = VMLayer

    def test_open(self):
        """Execute a program that invokes open system call and check that it appears in the event stream"""

        found = False
        needle = "/proc/cpuinfo"

        def open_hook(syscall):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_open":
                path_addr = syscall.args[0]
                path = process.libvmi.read_str_va(path_addr, process.pid)
                logging.debug("open: %s", path)
                if path == needle:
                    found = True

        hooks = {"open": open_hook}
        self.run_binary_test("test_open", hooks)
        self.assertTrue(found)

    def test_write(self):
        """Look for a write system call with a predetermined buffer"""

        found = False
        needle = b"Hello World!"

        def write_hook(syscall):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_write":
                buf_addr = syscall.args[1]
                buf_len = syscall.args[2]
                buf = process.libvmi.read_va(buf_addr, process.pid, buf_len)
                logging.debug("write (buffer size %d): \"%s\"", buf_len, buf)
                if buf == needle:
                    found = True

        hooks = {"write": write_hook}
        self.run_binary_test("test_write", hooks)
        self.assertTrue(found)
    
    def test_unlink(self):
        """Look for unlink with predefined path name"""

        found = False
        needle = "/tmp/test_unlink.tmp"

        def unlink_hook(syscall):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_unlink":
                path_addr = syscall.args[0]
                path = process.libvmi.read_str_va(path_addr, process.pid)
                logging.debug("unlink: %s", path)
                if path == needle:
                    found = True

        hooks = {"unlink": unlink_hook}
        self.run_binary_test("test_unlink", hooks)
        self.assertTrue(found)

    def run_binary_test(self, binary, hooks=None):
        binary_path = os.path.join(self.script_dir, "linux_binaries", "build", binary)
        self.vm.cdrom.set_executable(binary_path)

        events, exec_time = self.vm.run_test(hooks=hooks)

        with open("{}.json", "w") as f:
            json.dump(events, f, indent=4)

        if exec_time is not None:
            logging.info("Test execution time %s", exec_time)

        return events