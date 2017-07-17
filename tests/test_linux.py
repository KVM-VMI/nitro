import os.path
import sys
import unittest
import logging
import json
from layers import LinuxVMLayer

sys.path.insert(1, os.path.realpath('..'))

class TestLinux(unittest.TestCase):
    layer = LinuxVMLayer

    def test_hook_open(self):
        """Execute a program that invokes open system call and check that it appears in the event stream"""
        binary_path = os.path.join(self.script_dir, "linux_binaries", "build", "test_open")
        self.vm.cdrom.set_executable(binary_path)

        events, exec_time = self.vm.run_test()

        with open("events.json", "w") as f:
            json.dump(events, f, indent=4)
        
        if exec_time is not None:
            logging.info("Test execution time %d", exec_time)

        event_found = next(e for e in events
                           if e.get("process") and
                              e["process"]["name"] == "test_open")
        self.assertTrue(event_found)
