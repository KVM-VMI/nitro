#!/usr/bin/env python2

"""

Usage:
  symbols.py <ram_dump>

Options:
  -h --help     Show this screen.

"""

import logging

# logging.basicConfig(level=logging.DEBUG)

import ipdb
import StringIO 
import json

from docopt import docopt
from rekall import session
from rekall import plugins


def main(args):
    ram_dump = args['<ram_dump>']
    s = session.Session(
            filename=ram_dump,
            autodetect=["rsds"],
            logger=logging.getLogger(),
            autodetect_scan_length=18446744073709551616,
            format='data',
            profile_path=[
                "/home/developer/.rekall_cache",
                "http://profiles.rekall-forensic.com"   
            ])

    pshead = s.GetParameter("PsActiveProcessHead")

    output = StringIO.StringIO()

    s.RunPlugin("ssdt", output=output)

    jdata = json.loads(output.getvalue())

    addr = pshead.Flink.GetData()
    # jdata.append({"PsActiveProcessHead" :})

    with open('output.json', 'w') as f:
        json.dump(jdata, f)

if __name__ == '__main__':
    main(docopt(__doc__))
