Command-line Interface
======================

In addition to being usable as an API for virtual machine introspection, Nitro
can be used as a command-line tool. In this form of operation, Nitro can attach
to running virtual machines and output information about all the events it sees.

The command line interface can be invoked using the ``nitro`` command. To attach
to a running ``libvirt`` domain named ``nitro_ubuntu1604`` and saving the
generated event stream into ``events.json``, run:

::

   $ nitro -o events.json nitro_ubuntu1604

If the output file is not specified, Nitro defaults to printing the event stream
to the standard output.

.. cmdoption :: -o FILE, --out FILE

   Specify where the recorded events are saved. If not present, Nitro prints the
   events to the standard output.

By default, Nitro tries to use a suitable backend based on the guest's operating
system for semantic information and enrich the raw low-level events. The
``--nobackend`` option is provided to disable this semantic translation.

.. cmdoption :: --nobackend

   Disable the use of analysis back ends. In this mode, Nitro will only gather
   low-level event data.
