import os
import sys
import unittest
import logging
import json
from layers import VMLayer
from vmtest_helper import WindowsVMTestHelper

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from nitro.backends.windows.types import ObjectAttributes, FileAccessMask

class TestWindows(unittest.TestCase):
    domain_name = "nitro_win7x64"
    test_helper = WindowsVMTestHelper
    layer = VMLayer

    def test_hook_openfile(self):
        file_path = 'C:\\Program Files\\Windows Sidebar\\Gadgets\\PicturePuzzle.Gadget\\en-US\\gadget.xml'
        script = 'Get-Content \"{}\"'.format(file_path)
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtOpenFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtOpenFile': enter_NtOpenFile,
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook') and e['hook']['object_name'].find(file_path) != -1]
        self.assertTrue(event_found)
        # get all opened files and log them for debug
        opened_files = [e['hook']['object_name'] for e in events if e.get('hook')]
        logging.info('opened_files {}'.format(json.dumps(opened_files, indent=4)))

    def test_hook_openkey(self):
        key_path = 'Software\\ABCDMagicKey1234'
        script = 'New-Item \"HKCU:\\{}\" -Force | New-ItemProperty -Name foobar -Value true -PropertyType STRING -Force'.format(key_path)
        self.vm.cdrom.set_script(script, powershell=True)

        def enter_NtOpenKey(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            syscall.hook = buffer

        def enter_NtCreateKey(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            syscall.hook = buffer

        hooks = {
            'NtOpenKey': enter_NtOpenKey,
            'NtCreateKey': enter_NtCreateKey,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook') and e['hook'].find(key_path) != -1]
        self.assertTrue(event_found)

    def test_createfile_read(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_read.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'GENERIC_READ' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_write(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_write.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'GENERIC_WRITE' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_execute(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_execute.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'GENERIC_EXECUTE' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_all(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_all.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'GENERIC_ALL' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_append(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_append.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'FILE_APPEND_DATA' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_file_execute(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_file_execute.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'FILE_EXECUTE' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_read_data(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_read_data.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'FILE_READ_DATA' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_createfile_write_data(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_write_data.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtCreateFile(syscall):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'FILE_WRITE_DATA' in e['hook']['access']]
        self.assertTrue(event_found)

    def test_deletefile(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'delete_file.exe')
        self.vm.cdrom.set_executable(binary_path)

        def enter_NtOpenFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        def enter_NtCreateFile(syscall, backend):
            DesiredAccess = syscall.args[1]
            object_attributes = syscall.args[2]
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        hooks = {
            'NtOpenFile': enter_NtOpenFile,
            'NtCreateFile': enter_NtCreateFile,
        }
        events, exec_time = self.vm.run_test(enter_hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook')
                       and e['hook']['object_name'].find('foobar.txt') != -1
                       and 'DELETE' in e['hook']['access']]
        self.assertTrue(event_found)
