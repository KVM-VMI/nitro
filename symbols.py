#!/usr/bin/env python2

"""

Usage:
  symbols.py <ram_dump>

Options:
  -h --help     Show this screen.

"""

import logging
import re
import StringIO 
import json

# logging.basicConfig(level=logging.DEBUG)


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
    
    pshead_links = {}
    # '<_LIST_ENTRY Pointer to [0xFADFF410D120] (Flink)>'
    m = re.match(r'<_LIST_ENTRY Pointer to \[0x(.*)\] \(Flink\)>', repr(pshead.Flink))
    pshead_links['Flink'] = m.group(1)
    m = re.match(r'<_LIST_ENTRY Pointer to \[0x(.*)\] \(Blink\)>', repr(pshead.Blink))
    pshead_links['Blink'] = m.group(1)
    jdata.append({"PsActiveProcessHead" : pshead_links})

    with open('output.json', 'w') as f:
        json.dump(jdata, f)

if __name__ == '__main__':
    main(docopt(__doc__))
