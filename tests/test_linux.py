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
        events = self.run_binary_test("test_open")
        result = next(
            e for e in events
            if e.get("process")
            and e["process"]["name"] == "test_open"
            and e["name"] == "open")
        self.assertTrue(result)

    def test_write(self):
        """Look for a write system call with a predetermined buffer"""

        # TODO: look for the string
        def write_hook(syscall):
            pass

        hooks = {"write": write_hook}
        events = self.run_binary_test("test_write", hooks)
        result = next(
            e for e in events
            if e.get("process")
            and e["process"]["name"] == "write_open"
            and e["name"] == "write")
        self.assertTrue(result)

    def run_binary_test(self, binary, hooks=None):
        binary_path = os.path.join(self.script_dir, "linux_binaries", "build", binary)
        self.vm.cdrom.set_executable(binary_path)

        events, exec_time = self.vm.run_test(hooks=hooks)

        with open("{}.json", "w") as f:
            json.dump(events, f, indent=4)

        if exec_time is not None:
            logging.info("Test execution time %d", exec_time)

        return events