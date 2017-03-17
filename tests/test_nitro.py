#!/usr/bin/env python3

# stdlib
import os
import sys
import re
import stat
import logging
import subprocess
import shutil
import time
import xml.etree.ElementTree as tree
import json
from threading import Thread, Event
import socket
from tempfile import TemporaryDirectory, NamedTemporaryFile
from pathlib import Path
import datetime
import unittest

# 3rd
import libvirt

# local
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from nitro.nitro import Nitro
from nitro.backend import Backend
from nitro.event import SyscallDirection


def wait_winrm(ip_addr, opened=True):
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        state = s.connect_ex((ip_addr, 5985))
        if state == 0 and opened:
            break
        elif state != 0 and not opened:
            # received a RST, port is closed
            break
        time.sleep(1)


class CDROM:

    def __init__(self):
        # create cdrom dir
        self.cdrom_dir_tmp = TemporaryDirectory()
        self.tmp_dir = TemporaryDirectory()
        # give qemu permission to execute and read in this directory
        os.chmod(self.tmp_dir.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                                    stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
        self.cdrom_dir = self.cdrom_dir_tmp.name
        self.cdrom_iso_tmp = None
        # write autorun.inf
        self.write_autorun()
        # write main script
        self.write_run_bat()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()

    def cleanup(self):
        self.cdrom_iso_tmp.close()
        self.tmp_dir.cleanup()
        self.cdrom_dir_tmp.cleanup()

    def write_autorun(self):
        # write autorun.inf
        content = """
[autorun]
open=run.bat
"""[1:].replace('\n', '\r\n')
        autorun_path = os.path.join(self.cdrom_dir, 'autorun.inf')
        with open(autorun_path, 'w') as f:
            f.write(content)

    def write_run_bat(self):
        # write autorun.inf
        content = """
CALL test.bat
sc stop winrm
"""[1:].replace('\n', '\r\n')
        run_bat_path = os.path.join(self.cdrom_dir, 'run.bat')
        with open(run_bat_path, 'w') as f:
            f.write(content)

    def set_script(self, script, powershell=False):
        script = script.replace('\n', '\r\n')
        if powershell:
            test_bat_content = 'powershell -File test.ps1'
            # write test.ps1
            test_ps1_path = os.path.join(self.cdrom_dir, 'test.ps1')
            with open(test_ps1_path, 'w') as f:
                f.write(script)
        else:
            test_bat_content = script
        test_bat_path = os.path.join(self.cdrom_dir, 'test.bat')
        with open(test_bat_path, 'w') as f:
            f.write(test_bat_content)

    def set_executable(self, exe_path):
        exe_path = Path(exe_path)
        # copy executable
        exe_path_cdrom = os.path.join(self.cdrom_dir, exe_path.name)
        shutil.copyfile(str(exe_path), exe_path_cdrom)
        # write test.bat
        content = """
{}
""".format(exe_path.name)[1:].replace('\n', '\r\n')
        test_bat_path = os.path.join(self.cdrom_dir, 'test.bat')
        with open(test_bat_path, 'w') as f:
            f.write(content)

    def generate_iso(self, cleanup=True):
        self.cdrom_iso_tmp = NamedTemporaryFile(delete=False, dir=self.tmp_dir.name)
        cdrom_iso = self.cdrom_iso_tmp.name
        # chmod to be r/w by everyone
        # so we can remove the file even when qemu takes the ownership

        # generate iso
        genisoimage_bin = shutil.which('genisoimage')
        if genisoimage_bin is None:
            raise Exception('Cannot find genisoimage executable')
        args = [genisoimage_bin, '-o', cdrom_iso, '-iso-level', '4', self.cdrom_dir]
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.debug('ISO generated at {}'.format(cdrom_iso))
        # cleanup
        if cleanup:
            self.cdrom_dir_tmp.cleanup()
        return cdrom_iso


class VMTest:

    def __init__(self, domain):
        # looking for a nitro_<vm> in qemu:///system
        self.domain = domain

    def wait_for_ip(self):
        # find MAC address
        dom_elem = tree.fromstring(self.domain.XMLDesc())
        mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get('address')
        logging.debug('MAC address : {}'.format(mac_addr))
        while True:
            output = subprocess.check_output(["ip", "neigh"])
            for line in output.splitlines():
                m = re.match('(.*) dev [^ ]+ lladdr {} STALE'.format(mac_addr), line.decode('utf-8'))
                if m:
                    ip_addr = m.group(1)
                    return ip_addr
            time.sleep(1)

    def mount_cdrom(self, cdrom_path):
        logging.info('Mounting CDROM image')
        dom_elem = tree.fromstring(self.domain.XMLDesc())
        # find cdrom
        cdrom_elem = dom_elem.find("./devices/disk[@device='cdrom']")
        # find source
        source_elem = cdrom_elem.find('./source')
        if source_elem is None:
            tree.SubElement(cdrom_elem, 'source')
            source_elem = cdrom_elem.find('./source')
        source_elem.set('file', cdrom_path)
        new_xml = tree.tostring(cdrom_elem).decode('utf-8')
        self.domain.updateDeviceFlags(new_xml, libvirt.VIR_DOMAIN_AFFECT_LIVE)

    def run(self, cdrom_iso, analyze=True, idle=False):
        # start domain
        logging.info('Testing {}'.format(self.domain.name()))
        self.domain.create()
        # wait for IP address
        ip = self.wait_for_ip()
        logging.info('IP address : {}'.format(ip))
        # wait for WinRM to be available
        wait_winrm(ip, True)
        if idle:
            # wait for idle
            idle_wait = 60 * 5
            logging.info('Waiting for Windows to be idle (5 min)')
            time.sleep(idle_wait)
        # run nitro before inserting CDROM
        nitro = NitroThread(self.domain, analyze)
        nitro.start()
        # mount cdrom, test is executed
        self.mount_cdrom(cdrom_iso)
        # test is executing under Nitro monitoring
        # wait on WinRM to be closed
        wait_winrm(ip, False)
        # # wait for nitro thread to terminate properly
        nitro.stop()
        self.domain.shutdown()
        # stop domain
        while self.domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
            time.sleep(1)
        result = (nitro.events, nitro.total_time)
        return result


class NitroThread(Thread):

    def __init__(self, domain, analyze):
        super().__init__()
        self.domain = domain
        self.analyze_enabled = analyze
        if self.analyze_enabled:
            self.backend = Backend(self.domain)
        self.stop_request = Event()
        self.total_time = None
        self.events = []

    def run(self):
        # start timer
        start_time = datetime.datetime.now()
        with Nitro(self.domain) as nitro:
            nitro.set_traps(True)
            for event in nitro.listen():
                if self.analyze_enabled:
                    syscall = self.backend.process_event(event)
                    ev_info = syscall.info()
                else:
                    ev_info = event.info()
                self.events.append(ev_info)
                if self.stop_request.isSet():
                    break
        # stop timer
        stop_time = datetime.datetime.now()
        self.total_time = str(stop_time - start_time)

    def stop(self):
        self.stop_request.set()
        self.join()
        self.backend.stop()


class TestNitro(unittest.TestCase):

    def setUp(self):
        con = libvirt.open('qemu:///system')
        domain = con.lookupByName('nitro_win7x64')
        self.vm_test = VMTest(domain)
        self.cdrom = CDROM()
        # clean old test directory
        test_dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self._testMethodName)
        shutil.rmtree(test_dir_path, ignore_errors=True)
        os.makedirs(test_dir_path, exist_ok=True)
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

    def test_list_system32_analyze(self):
        script = 'Get-ChildItem -Path C:\\windows'
        self.cdrom.set_script(script, powershell=True)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time = self.vm_test.run(cdrom_iso)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

    def test_binary(self):
        binary_path = ''
        self.cdrom.set_executable(binary_path)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time = self.vm_test.run(cdrom_iso, analyze=False)
        # writing events
        logging.debug('Writing events...')
        with open('events.json', 'w') as f:
            json.dump(events, f, indent=4)
        logging.info('Test execution time {}'.format(exec_time))

