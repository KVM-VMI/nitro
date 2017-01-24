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

    print(json.dumps(jdata))

if __name__ == '__main__':
    main(docopt(__doc__))
