#!/usr/bin/env python3

import os
import sys
import re
import logging
import subprocess
import time
import xml.etree.ElementTree as tree
import threading
from datetime import timedelta

import libvirt
import winrm

# fix timeout
import requests
old_req_send = requests.Session.send

# force a fixed timeout value
def send_fix_timeout(self, request, **kwargs):
    return old_req_send(self, request, timeout=3000)
# patch
requests.Session.send = send_fix_timeout

# add parent directory
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from libnitro import Nitro


NB_TEST = 1

def get_ip(mac_addr):
    while True:
        output = subprocess.check_output(["ip", "neigh"])
        for line in output.splitlines():
            m = re.match('(.*) dev [^ ]+ lladdr {} STALE'.format(mac_addr), line.decode('utf-8'))
            if m:
                ip_addr = m.group(1)
                return ip_addr
        time.sleep(1)


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


def run_nitro(func):
    def wrapper(domain, session):

        stop_request = threading.Event()
        def run_nitro_thread(stop_request):
            nb_syscalls = 0
            with Nitro(domain) as nitro:
                logging.info('Counting syscalls...')
                for event in nitro.listen():
                    if event.direction() == 'ENTER':
                        nb_syscalls += 1
                    if stop_request.isSet():
                        break
            logging.info('Nb Syscalls : {}'.format(nb_syscalls))

        # start thread
        thread = threading.Thread(target=run_nitro_thread, args=(stop_request,))
        thread.start()

        result = func(domain, session)

        # wait for thread to stop
        stop_request.set()
        thread.join()
        return result
    return wrapper


@run_nitro
def run_test(domain, session):
    logging.info('Running test command')
    # command that will be executed in user desktop session
    exe = "c:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
    args = ["-Command", "Get-ChildItem -Path C:\\windows"]
    
    # prepare psexec command
    args_psexec_display = ["-accepteula", "-s", "-i", "1"]
    args_psexec = args_psexec_display
    args_psexec.append(exe)
    args_psexec.extend(args)
    logging.debug('Executing PowerShell command : {}'.format(args[1]))
    start = None
    end = None
    while True:
        try:
            start = time.time()
            session.run_cmd('c:\\pstools\\PsExec64.exe', args_psexec)
            end = time.time()
        except winrm.exceptions.WinRMTransportError:
            logging.debug('WinRM error, retrying')
        else:
            break
    total_seconds = end - start
    return total_seconds
        


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

    total = 0
    for i in range(1,NB_TEST + 1):
        result = run_test(domain, s)
        logging.info('[TEST {}] Total execution time : {}'.format(i, timedelta(seconds=result)))
        total += result
    avg_total = total / NB_TEST
    logging.info('Average execution time : {}'.format(timedelta(seconds=avg_total)))


def main():
    con = libvirt.open('qemu:///system')
    for domain in con.listAllDomains():
        if re.match('nitro_.*', domain.name()):
            test_domain(domain)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    logging.getLogger("requests").setLevel(logging.WARNING)
    main()

