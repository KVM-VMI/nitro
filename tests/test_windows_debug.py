import os
import sys
import unittest
import logging
import json
from layers import WindowsVMLayer

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from nitro.win_types import ObjectAttributes, FileAccessMask
from nitro.backend import Backend

class TestWindowsDebug(unittest.TestCase):
    layer = WindowsVMLayer

    def test_NtCreateFile(self):
        script = 'New-Item c:\\Windows\\foobar.txt -type file -force'
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtCreateFile(syscall):
            named_args = ['KeyHandle', 'DesiredAccess', 'ObjectAttributes',
                    'IoStatusBlock', 'AllocationSize', 'FileAttributes',
                    'ShareAccess', 'CreateDisposition', 'CreateOptions',
                    'EaBuffer', 'EaLength']
            for i, name in enumerate(named_args):
                logging.debug('Arg[{}] {}: {}'.format(i, name, hex(syscall.args[i])))

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_NtCreateKey(self):
        key_path = 'Software\\ABCDMagicKey1234'
        script = 'New-Item \"HKCU:\\{}\" -Force | New-ItemProperty -Name foobar -Value true -PropertyType STRING -Force'.format(key_path)
        self.vm.cdrom.set_script(script, powershell=True)

        def callback(syscall):
            named_args = ['KeyHandle', 'DesiredAccess', 'ObjectAttributes',
                    'TitleIndex', 'Class', 'CreateOptions', 'Disposition']
            for i, name in enumerate(named_args):
                logging.debug('Arg[{}] {}: {}'.format(i, name, hex(syscall.args[i])))

        hooks = {
            'NtCreateKey': callback,
        }
        events, exec_time = self.vm.run_test(hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_NtSetValueKey(self):
        key_path = 'Software\\ABCDMagicKey1234'
        script = 'New-Item \"HKCU:\\{}\" -Force | New-ItemProperty -Name foobar -Value true -PropertyType STRING -Force'.format(key_path)
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtSetValueKey(syscall):
            named_args = ['KeyHandle', 'ValueName', 'TitleIndex',
                    'Type', 'Data', 'DataSize']
            for i, name in enumerate(named_args):
                logging.debug('Arg[{}] {}: {}'.format(i, name, hex(syscall.args[i])))

        hooks = {
            'NtSetValueKey': enter_NtSetValueKey,
        }
        events, exec_time = self.vm.run_test(hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_read_write_arguments_memory(self):
        script = 'Get-ChildItem C:\\Windows'
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtCreateFile(syscall):
            named_args = ['KeyHandle', 'DesiredAccess', 'ObjectAttributes',
                    'IoStatusBlock', 'AllocationSize', 'FileAttributes',
                    'ShareAccess', 'CreateDisposition', 'CreateOptions',
                    'EaBuffer', 'EaLength']
            for i in range(4, 11):
                name = named_args[i]
                # read
                value = syscall.args[i]
                logging.debug('Arg[{}] {}: {}'.format(i, name, hex(value)))
                # write
                syscall.args[i] = value
                # read again
                new_value = syscall.args[i]
                if value != new_value:
                    raise RuntimeError('Inconsistent read/write')


        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_read_write_arguments_registers(self):
        script = 'Get-ChildItem C:\\Windows'
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtCreateFile(syscall):
            named_args = ['KeyHandle', 'DesiredAccess', 'ObjectAttributes',
                    'IoStatusBlock', 'AllocationSize', 'FileAttributes',
                    'ShareAccess', 'CreateDisposition', 'CreateOptions',
                    'EaBuffer', 'EaLength']
            for i in range(3):
                name = named_args[i]
                # read
                value = syscall.args[i]
                logging.debug('Arg[{}] {}: {}'.format(i, name, hex(value)))
                # write
                syscall.args[i] = value
                # read again
                new_value = syscall.args[i]
                if value != new_value:
                    raise RuntimeError('Inconsistent read/write')


        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_read_write_arguments(self):
        script = 'Get-ChildItem C:\\Windows'
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtCreateFile(syscall):
            named_args = ['KeyHandle', 'DesiredAccess', 'ObjectAttributes',
                    'IoStatusBlock', 'AllocationSize', 'FileAttributes',
                    'ShareAccess', 'CreateDisposition', 'CreateOptions',
                    'EaBuffer', 'EaLength']
            for i, name in enumerate(named_args):
                # read
                value = syscall.args[i]
                logging.debug('Arg[{}] {}: {}'.format(i, name, hex(value)))
                # write
                syscall.args[i] = value
                # read again
                new_value = syscall.args[i]
                if value != new_value:
                    raise RuntimeError('Inconsistent read/write')


        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
