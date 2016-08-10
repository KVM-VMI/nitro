#!/usr/bin/env python2

"""

Usage:
  symbols.py <ram_dump>

Options:
  -h --help     Show this screen.

"""

from sys import maxint
import logging
import re
import StringIO 
import json

# logging.basicConfig(level=logging.DEBUG)


from docopt import docopt
from rekall import session
from rekall import plugins

def get_symbol_addr(session, symbol):
    return hex(session.address_resolver.get_constant_object(symbol,
            "unsigned int").obj_offset)


def main(args):
    ram_dump = args['<ram_dump>']
    s = session.Session(
            filename=ram_dump,
            autodetect=["rsds"],
            logger=logging.getLogger(),
            autodetect_scan_length=maxint,
            format='data',
            profile_path=[
                "/home/developer/.rekall_cache",
                "http://profiles.rekall-forensic.com"   
            ])


    # get ssdt
    output = StringIO.StringIO()
    s.RunPlugin("ssdt", output=output)
    jdata = json.loads(output.getvalue())

    # get PsActiveProcessHead address
    pshead_addr = get_symbol_addr(s, 'nt!PsActiveProcessHead')

    # add to json
    kernel_symbols = {}
    kernel_symbols['PsActiveProcessHead'] = pshead_addr

    jdata.append(kernel_symbols)

    with open('output.json', 'w') as f:
        json.dump(jdata, f)

if __name__ == '__main__':
    main(docopt(__doc__))
