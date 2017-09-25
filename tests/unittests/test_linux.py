import sys
import os
import unittest

from unittest.mock import Mock

# local
sys.path.insert(1, os.path.realpath('../..'))
from nitro.backends.linux import LinuxBackend
from nitro.libvmi import Libvmi

# Mock common backend objects with some defaults

def translate_ksym2v(symbol):
    return {
        "sys_call_table": 0xc0ffee
    }[symbol]

def translate_v2ksym(symbol):
    return {}[symbol]

def translate_ksym2v(symbol):
    return {
        "sys_call_table": 0xc0ffee
    }[symbol]

def get_offset(symbol):
    return {
        "linux_tasks": 0x350,
        "linux_mm": 0x3a0,
        "linux_pid": 0x448,
        "linux_pgd": 0x40
    }[symbol]

# Is this safe, will this work without libvmi installed?
libvmi = Mock(spec=Libvmi,
              **{
                  "translate_ksym2v.side_effect": translate_ksym2v,
                  "translate_v2ksym.side_effect": translate_v2ksym,
                  "get_offset.side_effect": get_offset
              })

domain = Mock(**{
                  "vcpus.return_value": [[2]]
              })

class TestLinux(unittest.TestCase):
    def test_backend_creation(self):
        """Check that LinuxBackend can be creted."""
        backend = LinuxBackend(domain, libvmi)

        # Check that the created object gets its attributes from libvmi
        # Not really that useful...
        self.assertEqual(backend.tasks_offset, get_offset("linux_tasks"))
        self.assertEqual(backend.mm_offset, get_offset("linux_mm"))
        self.assertEqual(backend.pgd_offset, get_offset("linux_pgd"))

    def test_syscall_name(self):
        """Check that syscall names can be extracted from system call table."""
        backend = LinuxBackend(domain, libvmi)

        # Test syscall table inspection
        pass


