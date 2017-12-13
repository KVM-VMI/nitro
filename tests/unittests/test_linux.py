import os
import pathlib
import struct
import sys
import unittest
import logging

from unittest.mock import Mock, patch

# TODO:
# Make sure we do not end up importing anything that might cause problems
# in CI environment.

# We do not want to import libvirt
# Could we do this in a cleaner way?
sys.modules["libvirt"] = Mock()
sys.modules["nitro.backends.linux.process"] = Mock()
sys.modules["nitro.backends.linux.arguments"] = Mock()

# local
sys.path.insert(1, os.path.realpath('../..'))
from nitro.backends.linux import LinuxBackend
from nitro.backends.linux.backend import clean_name as linux_clean_name
from nitro.libvmi import Libvmi
from nitro.event import SyscallDirection
from nitro.syscall import Syscall

# Mock common backend objects with some defaults

def translate_v2ksym(symbol):
    return {
        0xffffffff8120f6a0: "SyS_read",
        0xffffffff8120f760: "SyS_write",
        0xffffffff8120ba50: "SyS_close",
        0xffffffff8120db70: "SyS_open"
    }[symbol]

def translate_ksym2v(symbol):
    return {
        "sys_call_table": 0xc0ffee,
        "init_task": 0x1000
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
        """Check that LinuxBackend can be created."""
        backend = LinuxBackend(domain, libvmi)

        # Check that the created object gets its attributes from libvmi
        # Not really that useful...
        self.assertEqual(backend.tasks_offset, get_offset("linux_tasks"))
        self.assertEqual(backend.mm_offset, get_offset("linux_mm"))
        self.assertEqual(backend.pgd_offset, get_offset("linux_pgd"))

    def test_syscall_name(self):
        """Check that syscall names can be extracted from system call table."""
        backend = LinuxBackend(domain, libvmi)
        # The sample file is extracted from the Ubuntu image used integration tests
        with get_resource_path("syscall_table_sample.bin").open("rb") as handle:
            memory = handle.read()
        base = translate_ksym2v("sys_call_table")
        def read_addr_va(addr, pid):
            start = addr - base
            return struct.unpack("P", memory[start:start+8])[0]
        with patch.object(backend.libvmi, "read_addr_va", side_effect=read_addr_va):
            self.assertEqual(backend.get_syscall_name(0), "SyS_read")
            self.assertEqual(backend.get_syscall_name(1), "SyS_write")
            self.assertEqual(backend.get_syscall_name(2), "SyS_open")
            self.assertEqual(backend.get_syscall_name(3), "SyS_close")

    def test_associate_process(self):
        """Test process association."""

        # This is kind of silly, but I think it codifies some of the
        # relationships between addresses that the backend uses.
        # Obviously a more robust test would be desirable

        backend = LinuxBackend(domain, libvmi)
        init_task = translate_ksym2v("init_task")
        mm_offset = get_offset("linux_mm")
        pgd_offset = get_offset("linux_pgd")
        tasks_offset = get_offset("linux_tasks")
        init_task_mm = 0x6060
        init_task_mm_pgd = 0x7070

        # Fake memory
        def read_addr_va(addr, pid):
            return {
                init_task + mm_offset: init_task_mm, # mm for init task
                init_task_mm + pgd_offset: init_task_mm_pgd,
                init_task + tasks_offset: init_task + tasks_offset
            }[addr]

        def translate_kv2p(pgd):
            return pgd + 0x100

        with patch.object(backend.libvmi, "read_addr_va", side_effect=read_addr_va), \
             patch.object(backend.libvmi, "translate_kv2p", side_effect=translate_kv2p):
            process = backend.associate_process(init_task_mm_pgd + 0x100)
            self.assertIsNotNone(process)

    def test_check_caches_flushed(self):
        """Check that libvmi caches are flushed."""
        backend = LinuxBackend(domain, libvmi)
        event = Mock(direction=SyscallDirection.exit, vcpu_nb=0)

        with patch.object(LinuxBackend, "associate_process"), \
             patch.object(LinuxBackend, "get_syscall_name", return_value="SyS_write"):
            backend.process_event(event)

        libvmi.v2pcache_flush.assert_called_once_with()
        libvmi.pidcache_flush.assert_called_once_with()
        libvmi.rvacache_flush.assert_called_once_with()
        libvmi.symcache_flush.assert_called_once_with()

    def test_process_event(self):
        """Test that the event handler returns a syscall object with somewhat sensible content"""
        backend = LinuxBackend(domain, libvmi)
        event = Mock(direction=SyscallDirection.enter, vcpu_nb=0)

        with patch.object(LinuxBackend, "associate_process"), \
             patch.object(LinuxBackend, "get_syscall_name", return_value="SyS_write"):
            syscall = backend.process_event(event)

        self.assertEqual(syscall.name, "write")
        self.assertEqual(syscall.full_name, "SyS_write")
        self.assertIsInstance(syscall, Syscall)

    def test_clean_name(self):
        """Test that system call handler names are properly cleaned."""
        self.assertEqual(linux_clean_name("SyS_foo"), "foo")
        self.assertEqual(linux_clean_name("sys_bar"), "bar")


