import os
import pathlib
import struct
import sys
import unittest
import logging

from unittest.mock import Mock, patch

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
    return {
        18446744071581005472: "SyS_read",
        18446744071581005664: "SyS_write",
        18446744071580990032: "SyS_close",
        18446744071580998512: "SyS_open"
    }[symbol]

def translate_ksym2v(symbol):
    return {
        "sys_call_table": 0xc0ffee,
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

def get_resource_path(name):
    return pathlib.Path(__file__).parent.joinpath("resources", name)

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
        with get_resource_path("syscall_table_sample.bin").open("rb") as handle:
            memory = handle.read()
        base = translate_ksym2v("sys_call_table")
        def read_addr_va(addr, pid):
            start = addr - base
            return struct.unpack("P", memory[start:start+8])[0]
        with patch.object(backend.libvmi, "read_addr_va", side_effect=read_addr_va) \
             as mock_read_addr_va:
            self.assertEqual(backend.get_syscall_name(0), "SyS_read")
            self.assertEqual(backend.get_syscall_name(1), "SyS_write")
            self.assertEqual(backend.get_syscall_name(2), "SyS_open")
            self.assertEqual(backend.get_syscall_name(3), "SyS_close")


