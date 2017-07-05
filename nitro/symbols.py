#!/usr/bin/env python2

"""

Usage:
  symbols.py <ram_dump>

Options:
  -h --help     Show this screen.

"""

import os
import logging
import StringIO 
import json
from collections import defaultdict

# logging.basicConfig(level=logging.DEBUG)


from docopt import docopt
from rekall import session
from rekall import plugins

def main(args):
    ram_dump = args['<ram_dump>']
    home = os.getenv('HOME')
    # we need to make sure the directory exists otherwise rekall will complain
    # when we specify it in the profile_path
    local_cache_path = os.path.join(home, '.rekall_cache')
    try:
        os.makedirs(local_cache_path)
    except OSError: # already exists
        pass

    s = session.Session(
            filename=ram_dump,
            autodetect=["rsds"],
            logger=logging.getLogger(),
            autodetect_build_local='none',
            format='data',
            profile_path=[
                local_cache_path,
                "http://profiles.rekall-forensic.com"
            ])

    symbols = {}
    output = StringIO.StringIO()
    s.RunPlugin("ssdt", output=output)
    symbols['syscall_table'] = json.loads(output.getvalue())
    symbols['offsets'] = get_offsets(s)

    print(json.dumps(symbols))


def get_offsets(session):
    offsets = defaultdict(dict)
    offsets['KPROCESS']['DirectoryTableBase'] = session.profile.get_obj_offset('_KPROCESS',
                                                                   'DirectoryTableBase')
    offsets['EPROCESS']['ActiveProcessLinks'] = session.profile.get_obj_offset('_EPROCESS',
                                                      'ActiveProcessLinks')
    offsets['EPROCESS']['ImageFileName'] = session.profile.get_obj_offset('_EPROCESS',
                                                              'ImageFileName')
    offsets['EPROCESS']['UniqueProcessId'] = session.profile.get_obj_offset('_EPROCESS',
                                                   'UniqueProcessId')
    return offsets

if __name__ == '__main__':
    main(docopt(__doc__))
