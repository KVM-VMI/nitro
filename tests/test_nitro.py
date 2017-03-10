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
from threading import Thread, Event
import socket
from tempfile import TemporaryDirectory, NamedTemporaryFile
import datetime
import unittest

# 3rd
import libvirt

# local
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from nitro.nitro import Nitro
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

    def configure_test(self, script):
        script = script.replace('\n', '\r\n')
        test_bat_path = os.path.join(self.cdrom_dir, 'test.bat')
        with open(test_bat_path, 'w') as f:
            f.write(script)

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

    def run(self, cdrom_iso, idle=True):
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
        nitro = NitroThread(self.domain)
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
        result = (nitro.events, nitro.total_time, nitro.nb_syscall)
        return result


class NitroThread(Thread):

    def __init__(self, domain):
        super().__init__()
        self.domain = domain
        self.stop_request = Event()
        self.total_time = None
        self.events = []
        self.nb_syscall = 0

    def run(self):
        # start timer
        start_time = datetime.datetime.now()
        with Nitro(self.domain) as nitro:
            nitro.set_traps(True)
            for event in nitro.listen():
                self.events.append(event)
                if event.direction == SyscallDirection.enter:
                    self.nb_syscall += 1
                if self.stop_request.isSet():
                    break
        # stop timer
        stop_time = datetime.datetime.now()
        self.total_time = str(stop_time - start_time)
        logging.info('Nb Syscalls : {}'.format(self.nb_syscall))

    def stop(self):
        self.stop_request.set()
        self.join()


class TestNitro(unittest.TestCase):

    def setUp(self):
        con = libvirt.open('qemu:///system')
        domain = con.lookupByName('nitro_win7x64')
        self.vm_test = VMTest(domain)
        self.cdrom = CDROM()

    def tearDown(self):
        self.cdrom.cleanup()

    def test_nitro(self):
        script = 'powershell -Command \"Get-ChildItem -Path C:\\windows\\system32"'
        self.cdrom.configure_test(script)
        cdrom_iso = self.cdrom.generate_iso()
        events, exec_time, nb_syscall = self.vm_test.run(cdrom_iso, idle=False)
        logging.info('Test execution time {}'.format(exec_time))

