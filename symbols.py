#!/usr/bin/env python2

"""

Usage:
  symbols.py <ram_dump>

Options:
  -h --help     Show this screen.

"""

import os
import logging
import re
import StringIO 
import json

# logging.basicConfig(level=logging.DEBUG)


from docopt import docopt
from rekall import session
from rekall import plugins

def get_symbol_addr(session, symbol):
    return session.address_resolver.get_constant_object(symbol,
            "unsigned int").obj_offset


def main(args):
    ram_dump = args['<ram_dump>']
    s = session.Session(
            filename=ram_dump,
            autodetect=["rsds"],
            logger=logging.getLogger(),
            cache_dir='{}/rekall_cache'.format(os.getcwd()),
            autodetect_build_local='basic',
            format='data',
            profile_path=[
                "http://profiles.rekall-forensic.com"   
            ])


    # get ssdt
    output = StringIO.StringIO()
    s.RunPlugin("ssdt", output=output)
    jdata = json.loads(output.getvalue())

    # get PsActiveProcessHead address
    pshead_addr = get_symbol_addr(s, 'nt!PsActiveProcessHead')
    # get eprocess ActiveProcessLinks offset
    activeprocesslinks_off = s.profile.get_obj_offset('_EPROCESS', 'ActiveProcessLinks')
    # get kprocess DirectoryTableBase offset
    directorytablebase_off = s.profile.get_obj_offset('_KPROCESS', 'DirectoryTableBase')
    # get eprocess ImageFileName offset
    imagefilename_off = s.profile.get_obj_offset('_EPROCESS', 'ImageFileName')
    # get eprocess UniqueProcessId offset
    uniqueprocessid_off = s.profile.get_obj_offset('_EPROCESS', 'UniqueProcessId')
    # # get KiArgumentTable
    # kiargs_addr = get_symbol_addr(s, 'nt!KiArgumentTable')
    # # get W32pArgumentTable
    # w32pargs_addr = get_symbol_addr(s, 'win32k!W32pArgumentTable')

    # add to json
    kernel_symbols = {}
    kernel_symbols['PsActiveProcessHead'] = pshead_addr
    kernel_symbols['ActiveProcessLinks_off'] = activeprocesslinks_off
    kernel_symbols['DirectoryTableBase_off'] = directorytablebase_off
    kernel_symbols['ImageFileName_off'] = imagefilename_off
    kernel_symbols['UniqueProcessId_off'] = uniqueprocessid_off
    # kernel_symbols['KiArgumentTable'] = kiargs_addr
    # kernel_symbols['W32pArgumentTable'] = w32pargs_addr

    jdata.append(kernel_symbols)

    with open('output.json', 'w') as f:
        json.dump(jdata, f)

if __name__ == '__main__':
    main(docopt(__doc__))
