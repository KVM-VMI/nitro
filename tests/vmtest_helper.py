import os
import sys
import logging
import time
import libvirt
import socket
import datetime
from threading import Thread, Event
import xml.etree.ElementTree as tree

# local
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from nitro.backend import Backend

SNAPSHOT_BASE = 'base'


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


class NitroThread(Thread):

    def __init__(self, domain, analyze=False, hooks=None):
        super().__init__()
        self.domain = domain
        self.analyze_enabled = analyze
        self.backend = Backend(self.domain, analyze)
        self.setup_hooks(hooks)
        self.stop_request = Event()
        self.total_time = None
        self.events = []

    def setup_hooks(self, hooks):
        if hooks:
            for name, callback in hooks.items():
                self.backend.define_hook(name, callback)

    def run(self):
        # start timer
        start_time = datetime.datetime.now()
        self.backend.nitro.set_traps(True)
        for event in self.backend.nitro.listen():
            if self.analyze_enabled:
                syscall = self.backend.process_event(event)
                ev_info = syscall.info()
            else:
                ev_info = event.info()
            self.events.append(ev_info)
            if self.stop_request.isSet():
                break
        self.backend.stop()
        # stop timer
        stop_time = datetime.datetime.now()
        self.total_time = str(stop_time - start_time)

    def stop(self):
        self.stop_request.set()
        self.join()


class VMTestHelper:

    def __init__(self, domain):
        # looking for a nitro_<vm> in qemu:///system
        self.domain = domain
        # revert to base snapshot if present
        try:
            snap = self.domain.snapshotLookupByName(SNAPSHOT_BASE)
            logging.info('Reverting to base snapshot')
            self.domain.revertToSnapshot(snap)
        except libvirt.libvirtError:
            logging.warning('Missing snapshot "{}"'.format(SNAPSHOT_BASE))

    def wait_for_ip(self, network_name='default'):
        # find MAC address
        dom_elem = tree.fromstring(self.domain.XMLDesc())
        mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get('address')
        logging.debug('MAC address : {}'.format(mac_addr))
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
        self.domain.updateDeviceFlags(new_xml, libvirt.VIR_DOMAIN_AFFECT_LIVE)

    def run(self, cdrom_iso, analyze=True, idle=False, hooks=None):
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
        nitro = NitroThread(self.domain, analyze, hooks)
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

    def force_shutdown(self):
        if self.domain.isActive():
            logging.info('Force VM shutdown, the test probably failed')
            self.domain.destroy()
