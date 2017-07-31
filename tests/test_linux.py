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

        last_handle = None
        found = False
        needle = b"Hello World!"

        # This is not really a good strategy
        # We cannot match this system call with the entry and connect path with its fd
        # Now we just hope that the process does not open anything else between this and the write call
        # In this case, it should be fine
        def open_hook(syscall):
            nonlocal last_handle
            process = syscall.process
            if process is not None and process.name == "test_write":
                logging.debug("open returned: %s", syscall.event.regs.rax)
                last_handle = syscall.event.regs.rax

        def write_hook(syscall):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_write":
                handle = syscall.args[0]
                buf_addr = syscall.args[1]
                buf_len = syscall.args[2]
                buf = process.libvmi.read_va(buf_addr, process.pid, buf_len)
                logging.debug("write (handle: %s, buffer size %d): \"%s\"", handle, buf_len, buf)
                if buf == needle and handle == last_handle:
                    found = True
        
        enter_hooks = {"write": write_hook}
        exit_hooks = {"open": open_hook}
        self.run_binary_test("test_write", enter_hooks, exit_hooks)
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

    def run_binary_test(self, binary, enter_hooks=None, exit_hooks=None):
        binary_path = os.path.join(self.script_dir, "linux_binaries", "build", binary)
        self.vm.cdrom.set_executable(binary_path)

        events, exec_time = self.vm.run_test(enter_hooks=enter_hooks, exit_hooks=exit_hooks)

        with open("{}.json".format(binary), "w") as f:
            json.dump(events, f, indent=4)

        if exec_time is not None:
            logging.info("Test execution time %s", exec_time)

        return events