#!/usr/bin/env python3

"""
Usage:
  import_libvirt.py <qemu_image>

Options:
  -h --help     Show this screen.
"""

import os
import sys
import logging
import shutil
import xml.etree.ElementTree as tree

import libvirt
from docopt import docopt

NITRO_POOL_NAME = 'nitro'

def main(args):
    qemu_image = args['<qemu_image>']
    # check root
    if os.geteuid() != 0:
        logging.critical('Must be root to run this script')
        sys.exit(1)
    con = libvirt.open('qemu:///system')
    script_dir = os.path.dirname(os.path.realpath(__file__))
    storage_path = os.path.join(script_dir, 'images')
    # check for storage pool nitro
    try:
        storage = con.storagePoolLookupByName(NITRO_POOL_NAME)
    except libvirt.libvirtError:
        # create dir
        os.makedirs(storage_path, exist_ok=True)
        # build nitro pool xml
        path_elem = tree.Element('path')
        path_elem.text = storage_path
        target_elem = tree.Element('target')
        target_elem.append(path_elem)
        name_elem = tree.Element('name')
        name_elem.text = NITRO_POOL_NAME
        pool_elem = tree.Element('pool', attrib={'type': 'dir'})
        pool_elem.append(name_elem)
        pool_elem.append(target_elem)
        pool_xml = tree.tostring(pool_elem).decode('utf-8')
        # define it
        storage = con.storagePoolDefineXML(pool_xml)
        storage.create()
        storage.setAutostart(True)
    # check if domain is already defined
    image_name = os.path.basename(qemu_image)
    domain_name = 'nitro_{}'.format(image_name)
    try:
        domain = con.lookupByName(domain_name)
    except libvirt.libvirtError:
        # use our modified QEMU patched for VMI as emulator
        # it should be in kvm-vmi/qemu/x86_64-softmmu/qemu-system-x86_64
        qemu_bin_path = os.path.realpath(os.path.join(script_dir, '..', '..', 'qemu', 'x86_64-softmmu', 'qemu-system-x86_64'))
        # move image to nitro pool
        nitro_image_path = os.path.join(storage_path, '{}.qcow2'.format(image_name))
        shutil.move(qemu_image, nitro_image_path)
        with open('template_domain.xml') as templ:
            domain_xml = templ.read()
            domain_xml = domain_xml.format(domain_name, qemu_bin_path, nitro_image_path)
            con.defineXML(domain_xml)
            logging.info('Domain {} defined.'.format(domain_name))
    else:
        logging.info('Domain {} already defined'.format(domain_name))



if __name__ == '__main__':
    args = docopt(__doc__)
    logging.basicConfig(level=logging.DEBUG)
    main(args)
