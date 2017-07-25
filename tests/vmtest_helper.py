import os
import sys
import logging
import time
import libvirt
import socket
import datetime
from functools import partial
from threading import Thread, Event
import xml.etree.ElementTree as tree

# local
sys.path.insert(1, os.path.realpath('..'))
from nitro.nitro import Nitro
from nitro.libvmi import LibvmiError
from nitro.backends.backend import Backend
from cdrom import WindowsCDROM, LinuxCDROM

SNAPSHOT_BASE = 'base'

def wait_socket(port, ip_addr, opened=True):
    logging.info("Waiting for the monitored service on port %d to %s", port,
        "become available" if opened else "shutdown")
    prev_state = None
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        state = sock.connect_ex((ip_addr, port))
        if prev_state != state:
            logging.debug("Monitor state changed to %d", state)
            prev_state = state
        if state == 0 and opened:
            logging.info("Monitored service on port %d became available", port)
            break
        elif state != 0 and not opened:
            logging.info("Monitored service on port %d went down", port)
            break
        time.sleep(1)

wait_winrm = partial(wait_socket, 5985)
wait_sshd = partial(wait_socket, 22)

class NitroThread(Thread):

    def __init__(self, domain, analyze=False, hooks=None, ready_event=None):
        super().__init__()
        self.domain = domain
        self.analyze_enabled = analyze
        self.hooks = hooks or {}
        self.stop_request = Event()
        self.total_time = None
        self.events = []
        self.ready_event = ready_event

    def run(self):
        # start timer
        start_time = datetime.datetime.now()

        with Nitro(self.domain, self.analyze_enabled) as nitro:
            for name, callback in self.hooks.items():
                nitro.backend.define_hook(name, callback)
            nitro.listener.set_traps(True)
            if self.ready_event is not None:
                self.ready_event.set() # is this really necessary
            for event in nitro.listen():
                if self.analyze_enabled:
                    try:
                        syscall = nitro.backend.process_event(event)
                    except LibvmiError:
                        ev_info = event.as_dict()
                    else:
                        ev_info = syscall.as_dict()
                else:
                    ev_info = event.as_dict()
                self.events.append(ev_info)
                if self.stop_request.isSet():
                    logging.info("Stopping")
                    break

        # stop timer
        self.ready_event.clear()
        stop_time = datetime.datetime.now()
        self.total_time = str(stop_time - start_time)

    def stop(self):
        self.stop_request.set()
        self.join()


class VMTestHelper:
    def __init__(self, domain, wait, cdrom):
        self.domain = domain
        if self.domain.isActive():
            self.domain.destroy()
        # revert to base snapshot if present
        try:
            snap = self.domain.snapshotLookupByName(SNAPSHOT_BASE)
            logging.info('Reverting to base snapshot')
            self.domain.revertToSnapshot(snap)
        except libvirt.libvirtError:
            logging.warning('Missing snapshot "%s"', SNAPSHOT_BASE)
        # start domain
        logging.info('Testing {}'.format(self.domain.name()))
        self.domain.create()
        # wait for IP address
        self.ip = self.wait_for_ip()
        self.wait = wait
        logging.info('IP address: %s', self.ip)
        self.wait(self.ip, True)
        self.cdrom = cdrom

    def wait_for_ip(self, network_name='default'):
        # find MAC address
        dom_elem = tree.fromstring(self.domain.XMLDesc())
        mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get('address')
        logging.debug('MAC address: {}'.format(mac_addr))
        while True:
            net = self.domain.connect().networkLookupByName(network_name)
            leases = net.DHCPLeases()
            found = [l for l in leases if l['mac'] == mac_addr]
            if found:
                return found[0]['ipaddr']
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
        result = self.domain.updateDeviceFlags(new_xml, libvirt.VIR_DOMAIN_AFFECT_LIVE)
        logging.debug("updateDeviceFlags returned %s", result)

    def run_test(self, wait=True, analyze=True, hooks=None):
        """Run the test by mounting the cdrom into the guest
        if wait is True, it will run the Nitro thread and wait for the test to terminate.
        if wait is False, it will return an Event which will be set when the test will terminate"""
        # get iso
        cdrom_iso = self.cdrom.generate_iso()
        logging.debug("ISO path: %s", cdrom_iso)
        if wait:
            # run nitro before inserting CDROM
            ready = Event()
            nitro = NitroThread(self.domain, analyze, hooks, ready)
            nitro.start()
            # wait for nitro to attach before mounting the CDROM
            ready.wait()
            # mount the cdrom
            # the test is executed
            self.mount_cdrom(cdrom_iso)
            # wait on monitered to be closed
            self.wait(self.ip, False)
            # wait for nitro thread to terminate properly
            nitro.stop()
            result = (nitro.events, nitro.total_time)
            return result
        else:
            # mount the cdrom
            # the test is executed
            self.mount_cdrom(cdrom_iso)
            # create threading Event
            stop_event = Event()
            self.wait_thread = WaitThread(self.wait, False, self.ip, stop_event)
            self.wait_thread.start()
            return stop_event

    def stop(self):
        self.domain.shutdown()
        # stop domain
        while self.domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
            time.sleep(1)
        self.cdrom.cleanup()

class WindowsVMTestHelper(VMTestHelper):
    def __init__(self, domain):
        super().__init__(domain, wait_winrm, WindowsCDROM())

class LinuxVMTestHelper(VMTestHelper):
    def __init__(self, domain):
        super().__init__(domain, wait_sshd, LinuxCDROM())

class WaitThread(Thread):
    def __init__(self, wait, opened, ip, stop_event):
        super().__init__()
        self.wait = wait
        self.opened = opened
        self.ip = ip
        self.stop_event = stop_event

    def run(self):
        self.wait(self.ip, self.opened)
        self.stop_event.set()
