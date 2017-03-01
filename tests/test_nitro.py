#!/usr/bin/env python3

import os
import sys
import re
import logging
import subprocess
import shutil
import time
import xml.etree.ElementTree as tree
import threading
import socket
from tempfile import TemporaryDirectory, NamedTemporaryFile
from datetime import timedelta

import libvirt

# add parent directory
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from nitro.nitro import Nitro
from nitro.event import SyscallDirection


NB_TEST = 3

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

def get_ip(mac_addr):
    while True:
        output = subprocess.check_output(["ip", "neigh"])
        for line in output.splitlines():
            m = re.match('(.*) dev [^ ]+ lladdr {} STALE'.format(mac_addr), line.decode('utf-8'))
            if m:
                ip_addr = m.group(1)
                return ip_addr
        time.sleep(1)


def run_nitro_thread(domain, stop_request):
    nb_syscalls = 0
    with Nitro(domain) as nitro:
        nitro.set_traps(True)
        logging.info('Counting syscalls...')
        for event in nitro.listen():
            if event.direction == SyscallDirection.enter:
                nb_syscalls += 1
            if stop_request.isSet():
                break
    logging.info('Nb Syscalls : {}'.format(nb_syscalls))

def get_test_content():
    content = """
powershell -Command \"Get-ChildItem -Path C:\\windows\\system32"
"""[1:].replace('\n', '\r\n')
    return content


def test_domain(domain):
    # start domain
    logging.info('Testing {}'.format(domain.name()))
    domain.create()
    # find MAC address
    dom_elem = tree.fromstring(domain.XMLDesc())
    mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get('address')
    logging.debug('MAC address : {}'.format(mac_addr))
    # wait for IP address
    ip = get_ip(mac_addr)
    logging.info('IP address : {}'.format(ip))
    tmp_iso = build_cdrom()
    # wait for WinRM to be opened
    wait_winrm(ip, True)
    # wait for idle
    idle_wait = 60 * 5
    logging.info('Waiting for Windows to be idle (5 min)')
    time.sleep(idle_wait)
    # run nitro
    stop_request = threading.Event()
    thread = threading.Thread(target=run_nitro_thread, args=(domain, stop_request,))
    thread.start()
    # start timer
    start_time = time.time()
    # mount cdrom, test is executed
    mount_cdrom(domain, tmp_iso.name)
    # wait on WinRM to be closed
    wait_winrm(ip, False)
    # stop nitro
    stop_request.set()
    stop_time = time.time()
    # wait for nitro thread to terminate properly
    thread.join()
    domain.shutdown()
    result = stop_time - start_time
    # stop domain
    while domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
        time.sleep(1)
    tmp_iso.close()
    return result

def mount_cdrom(domain, cdrom_path):
    logging.info('Mounting CDROM image')
    dom_elem = tree.fromstring(domain.XMLDesc())
    # find cdrom
    cdrom_elem = dom_elem.find("./devices/disk[@device='cdrom']")
    # find source
    source_elem = cdrom_elem.find('./source')
    if source_elem is None:
        tree.SubElement(cdrom_elem, 'source')
        source_elem = cdrom_elem.find('./source')
    source_elem.set('file', cdrom_path)
    new_xml = tree.tostring(cdrom_elem).decode('utf-8')
    domain.updateDeviceFlags(new_xml, libvirt.VIR_DOMAIN_AFFECT_LIVE)


def build_cdrom():
    tmp_iso = NamedTemporaryFile(delete=False)
    # create tmp dir
    with TemporaryDirectory() as tmpdir:
        fill_cdrom(tmpdir)
        # generate iso
        genisoimage_bin = shutil.which('genisoimage')
        args = [genisoimage_bin, '-o', tmp_iso.name, '-iso-level', '4', tmpdir]
        subprocess.check_call(args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    logging.debug('ISO generated at {}'.format(tmp_iso.name))
    return tmp_iso



def fill_cdrom(tmpdir):
    # write autorun.inf
    content = """
[autorun]
open=run.bat
"""[1:].replace('\n', '\r\n')
    autorun_path = os.path.join(tmpdir, 'autorun.inf')
    with open(autorun_path, 'w') as f:
        f.write(content)
    # write run.bat
    content = get_test_content()
    end_test = """
sc stop winrm
"""[1:].replace('\n', '\r\n')
    content += end_test
    run_bat_path = os.path.join(tmpdir, 'run.bat')
    with open(run_bat_path, 'w') as f:
        f.write(content)


def main():
    con = libvirt.open('qemu:///system')
    for domain in con.listAllDomains():
        if re.match('nitro_.*', domain.name()):
            total = 0
            for i in range(1,NB_TEST + 1):
                result = test_domain(domain)
                logging.info('[TEST {}] Total execution time : {}'.format(i, timedelta(seconds=result)))
                total += result
            avg_total = total / NB_TEST
            logging.info('Average execution time : {}'.format(timedelta(seconds=avg_total)))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    main()

