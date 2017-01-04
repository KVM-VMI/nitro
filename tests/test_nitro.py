#!/usr/bin/env python


import os
import sys
import re
import logging
import subprocess
import time
import xml.etree.ElementTree as tree

import libvirt
import winrm

def get_ip(mac_addr):
    while True:
        output = subprocess.check_output(["ip", "neigh"])
        for line in output.splitlines():
            m = re.match('(.*) dev [^ ]+ lladdr {} STALE'.format(mac_addr), line)
            if m:
                ip_addr = m.group(1)
                return ip_addr
        time.sleep(5)


def start_stop(func):
    def wrapper(domain):
        # start domain
        logging.info('Testing {}'.format(domain.name()))
        domain.create()
        func(domain)
        # shutdown
        domain.shutdown()
        logging.info('Waiting for shutdown')
        while domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
            time.sleep(1)
    return wrapper


def run_test(domain, session):
    logging.info('Starting test')
    # command that will be executed in user desktop session
    exe = "c:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
    args = ["-Command", "Get-ChildItem -Path C: -Recurse -Force"]
    
    # prepare psexec command
    args_psexec_display = ["-accepteula", "-s", "-i", "1"]
    args_psexec = args_psexec_display
    args_psexec.append(exe)
    args_psexec.extend(args)
    session.run_cmd('c:\\pstools\\PsExec64.exe', args_psexec)
    logging.info('Test done')


@start_stop
def test_domain(domain):
    dom_elem = tree.fromstring(domain.XMLDesc())
    mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get('address')
    logging.debug('MAC address : {}'.format(mac_addr))
    # wait for winrm connection
    ip = get_ip(mac_addr)
    logging.info('IP address : {}'.format(ip))
    logging.info('Establishing a WinRM session')
    s = winrm.Session(ip, auth=('vagrant', 'vagrant'))
    s.run_cmd('ipconfig')
    run_test(domain, s)


def main():
    con = libvirt.open('qemu:///system')
    for domain in con.listAllDomains():
        if re.match('nitro_.*', domain.name()):
            test_domain(domain)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    logging.getLogger("requests").setLevel(logging.WARNING)
    main()

