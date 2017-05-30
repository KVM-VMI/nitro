#!/usr/bin/env python3

# stdlib
import os
import logging
import shutil
import json
import datetime
import unittest

# 3rd
import libvirt


from nitro.win_types import ObjectAttributes, FileAccessMask
from tests.cdrom import CDROM
from tests.vmtest_helper import VMTestHelper


class TestNitro(unittest.TestCase):

    def setUp(self):
        con = libvirt.open('qemu:///system')
        domain = con.lookupByName('nitro_win7x64')
        self.vm_test = VMTestHelper(domain)
        self.cdrom = CDROM()
        # clean old test directory
        test_dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self._testMethodName)
        shutil.rmtree(test_dir_path, ignore_errors=True)
        os.makedirs(test_dir_path, exist_ok=True)
        self.script_dir = os.path.dirname(os.path.realpath(__file__))
        # chdir into this directory for the test
        self.origin_wd = os.getcwd()
        os.chdir(test_dir_path)
        # create logging file handler
        self.f_handler = logging.FileHandler('test.log', mode='w')
        logging.getLogger().addHandler(self.f_handler)
        logging.info('Starting test at {}'.format(datetime.datetime.now()))

    def tearDown(self):
        self.cdrom.cleanup()
        # chdir back to original wd
        os.chdir(self.origin_wd)
        # force VM to stop if still running
        self.vm_test.force_shutdown()
        # remove file handler
        logging.info('Ending test at {}'.format(datetime.datetime.now()))
        logging.getLogger().removeHandler(self.f_handler)

    def test_list_system32_no_analyze(self):
        script = 'Get-ChildItem -Path C:\\windows\\system32'
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time = self.vm_test.run(cdrom_iso, analyze=False)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_list_windows_no_analyze(self):
        script = 'Get-ChildItem -Path C:\\windows'
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time = self.vm_test.run(cdrom_iso, analyze=False)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_list_system32_analyze(self):
        script = 'Get-ChildItem -Path C:\\windows\\system32'
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time = self.vm_test.run(cdrom_iso)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_list_windows_analyze(self):
        script = 'Get-ChildItem -Path C:\\windows'
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time = self.vm_test.run(cdrom_iso)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_hook_openfile(self):
        file_path = 'C:\\Program Files\\Windows Sidebar\\Gadgets\\PicturePuzzle.Gadget\\en-US\\gadget.xml'
        script = 'Get-Content \"{}\"'.format(file_path)
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtOpenFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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

    def test_createfile_read(self):
        binary_path = os.path.join(self.script_dir, 'binaries', 'createfile_read.exe')
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtOpenFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            access = FileAccessMask(DesiredAccess)
            syscall.hook = {
                'object_name': buffer,
                'access': access.rights
            }

        def enter_NtCreateFile(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
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
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
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

    def test_hook_openkey(self):
        key_path = 'Software\\ABCDMagicKey1234'
        script = 'New-Item \"HKCU:\\{}\" -Force | New-ItemProperty -Name foobar -Value true -PropertyType STRING -Force'.format(key_path)
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()

        def enter_NtOpenKey(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            syscall.hook = buffer

        def enter_NtCreateKey(syscall):
            KeyHandle, DesiredAccess, object_attributes = syscall.collect_args(3)
            obj = ObjectAttributes(object_attributes, syscall.process)
            buffer = obj.ObjectName.Buffer
            syscall.hook = buffer

        hooks = {
            'NtOpenKey': enter_NtOpenKey,
            'NtCreateKey': enter_NtCreateKey,
        }
        events, exec_time = self.vm_test.run(cdrom_iso, hooks=hooks)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))
        # checking if we find the event where the file is opened
        event_found = [e for e in events if e.get('hook') and e['hook'].find(key_path) != -1]
        self.assertTrue(event_found)
