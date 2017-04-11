#!/usr/bin/env python3

"""MemDump.

Usage:
  memdump.py [options] <vm_name>

Options:
  -h --help     Show this screen.
"""

import os
import stat
from docopt import docopt
import libvirt
from tempfile import NamedTemporaryFile, TemporaryDirectory

def main(args):
    vm_name = args['<vm_name>']
    # get domain from libvirt
    con = libvirt.open('qemu:///system')
    domain = con.lookupByName(vm_name)

    path = os.path.join(os.getcwd(), '{}.raw'.format(vm_name))
    with open(path, 'w') as f:
        # chmod to be r/w by everyone
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR |
                                stat.S_IRGRP | stat.S_IWGRP |
                                stat.S_IROTH | stat.S_IWOTH)
        # take a ram dump
        flags = libvirt.VIR_DUMP_MEMORY_ONLY
        dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
        domain.coreDumpWithFormat(path, dumpformat, flags)

if __name__ == '__main__':
    main(docopt(__doc__))
