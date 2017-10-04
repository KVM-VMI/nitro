Tutorial: Finding Out What Notepad is Doing
===========================================

In this chapter we will use Nitro to monitor what Windows Notepad. While this
might not be super interesting in itself, it demonstrates all the essential
techniques that will enable you to use Nitro for tackling real-world challenges.

Getting a Connection
--------------------

The first thing to do is to initialize Nitro and attach it to a virtual machine.
For the purposes of this tutorial, we expect the VM to be already running but we
could of course use libvirt APIs for automating seting up the environment.
Additionally, Nitro obviosly has to be in Python's module search path for any of
this to work.

.. literalinclude:: samples/tutorial-01.py

Here, we have imported the :class:`~.Nitro` class and used it to connect to a
libvirt domain named "Windows-VM". The optional ``introspection`` argument
indicates that we wish Nitro to create us a suitable analysis back end.

Inside the ``with`` statement, we enable traps. After the traps have been set,
we are ready to start listening for low-level :class:`~.NitroEvent` events from
the virtual machine.

So far, the code doesn't do anything too interesting as after the traps have
been set, Nitro exits gracefully as there is nothing more to do.

Letting the Events Flow
-----------------------

Next, lets extend the code to get some events from the target machine. We can
listen for events using :class:`~.Nitro` object's :meth:`~.Nitro.listen` method.
Internally, Nitro will use the :class:`~.Listener` it initialized for us.

.. literalinclude:: samples/tutorial-02.py

:meth:`~.Nitro.listen` will give us a stream of :class:`~.NitroEvent` events.
Each event describes a state of the machine when a system call entry or exit
happened. Here, we simply print a representation of each event received. This
should quickly print a lot of data about things happening inside the VM.

Understanding the Data
----------------------

While having all this data is certainly interesting, it does little to help us
in our mission to understand what Windows Notepad is doing while we use it to
edit text. There is simply too much data with too little useful information for
practical uses.

We can remedy the situation by calling in help the analysis back end that Nitro
helpfully created for us. Using the Windows analysis back end, we can transform
all the low-level events into something more useful.

.. literalinclude:: samples/tutorial-03.py

We now invoke back end's :meth:`~.WindowsBackend.process_event` method for each incoming event
to see what they are about. The method returns us a :class:`~.Syscall` event
with all the associated information. It is worth noting that digging around
virtual machine memory for information about events is a potentially challenging
task that may result in an error. It is a good practice to catch those. Here, if
everything went well, we will print the analysis result. This should result in
something little more understandable.

Looking for a Notepad
---------------------

Now we have everything we need to spot the bits of data that interest us. In
this case, we are interested in what Windows Notepad is doing when we open it.

.. literalinclude:: samples/tutorial-04.py

To find out Notepad related events we simply inspect the process property
associated with the event.
