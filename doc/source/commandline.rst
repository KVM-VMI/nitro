Command-line Interface
======================

In addition to being usable as an API for virtual machine introspection, Nitro
can be used as a command-line tool. In this form of operation, Nitro can attach
to running virtual machines and output information about all the events it sees.

The command line interface can be invoked using the ``main.py`` script, located
at the project root directory. To attach to a running libvirt domain named
``nitro_ubuntu1604`` and saving the generated event stream into ``events.json``,
run:

::

   $ ./main.py -o events.json nitro_ubuntu1604

If the output file is not specified, Nitro prints the event stream to standard
output.

.. cmdoption :: -o FILE, --out FILE

   Specify where the recorded events are saved.

By default, Nitro tries to use a suitable backend based on the guest's operating
system for extra information. If only low-level events are desired, the
``--nobackend`` option can be used to disable the extra analysis.
