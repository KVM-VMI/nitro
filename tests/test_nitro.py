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

def get_ip(domain):
    dom_elem = tree.fromstring(domain.XMLDesc())
    mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get('address')
    logging.debug('MAC address : {}'.format(mac_addr))
    while True:
        output = subprocess.check_output(["ip", "neigh"])
        for line in output.splitlines():
            m = re.match('(.*) dev [^ ]+ lladdr {} STALE'.format(mac_addr), line)
            if m:
                ip_addr = m.group(1)
                return ip_addr
        time.sleep(5)

def test_domain(domain):
    logging.info('Testing {}'.format(domain.name()))
    domain.create()
    # wait for winrm connection
    ip = get_ip(domain)
    logging.info('IP address : {}'.format(ip))
    logging.info('Establishing a WinRM session')
    s = winrm.Session(ip, auth=('vagrant', 'vagrant'))
    #args = ["-accepteula", "-s", "-i", "0", "c:\\windows\\system32\\calc.exe"]
    #s.run_cmd('c:\\pstools\\PsExec64.exe', args)
    s.run_cmd('ipconfig')
    domain.shutdown()
    logging.info('Waiting for shutdown')
    while domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
        time.sleep(5)

def main():
    con = libvirt.open('qemu:///system')
    for domain in con.listAllDomains():
        if re.match('nitro_.*', domain.name()):
            test_domain(domain)




if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()

