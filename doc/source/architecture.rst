Architecture
============

In this chapter, we take a look at how the project is structured and how the
different components fit together.

.. figure:: resources/nitro-architecture.svg
   :align: center
   :alt: Nitro's architecture

   Main components of Nitro. Listener receives low-level events from the kernel
   and passes them to the user through the frameworks namesake :class:`~.Nitro`
   class. The user can then decide to request for additional analysis from one
   of Nitro's back ends. Back ends transform the low-level events into system
   call events that contain bunch of useful information such as the process
   where the system call originated and offer an easy way to access the
   arguments of the call.

Virtual Machines
----------------

Nitro depends on `libvirt <https://libvirt.org>`__ to manage virtual machine
life cycle and configuration for it. Libvirt is responsible for keeping track of
machine definitions (what hardware is associated with the machine, what kind of
storage backend is being used, and how is the networking setup) and managing
QEMU instances for individual machines. Libvirt is structured as a daemon that
manages the actual virtual machines and responds to requests from clients such
as Nitro. Through the libvirt API, Nitro can start, stop and pause virtual
machines without having to directly deal with the hypervisor.

Internally, QEMU makes use of Linux's `KVM
<https://en.wikipedia.org/wiki/Kernel-based_Virtual_Machine>`__ feature for
supporting hardware assisted virtualization.

libvirt's `documentation <https://libvirt.org/docs.html>`__ offers additional
instructions on how to install and use it to effectively manage virtual
machines.

Nitro
-----

Event Listeners
---------------

Nitro's :class:`~.Listener` enables subscribing to events from the kernel
regarding a particular virtual machine. Listener issues a set of Nitro specific
`IOCTL <https://en.wikipedia.org/wiki/Ioctl>`__ commands to the KVM in order to
attach to a particular virtual CPU belonging to the virtual machine being
monitored.

Listener's :meth:`~.Listener.listen` method is a generator that produces a
series of :class:`~.NitroEvent` objects. These objects represent the low-level
state of the machine when the system call took place. They contain information
about the registers and whether the machine was entering or exiting a system
call. Additionally, the events record which of the (possibly many) virtual CPU's
associated with the machine was responsible the event.

Analysis Back ends
------------------

While knowing the register values is nice, for many real-world applications a
higher-level view of the system if often preferred. :class:`~.Backend` classes
transform the lower-level events that listeners produce into something more
useful. Since back ends depend on intricate knowledge of operating system
specific internals, they are specific to a particular operating system. Nitro
ships with back ends for 64-bit Windows 7 Professional and Linux. The
:class:`~.Nitro` class automatically initializes a suitable back end based on
the virtual machine's operating system.

Back ends :meth:`process_event` produces a :class:`~.Syscall` object based on
the :class:`~.NitroEvent` object given to it. System call objects offer a
higher-level representation of the machine's state by associating the event with
a logical name (``open``, ``write``, ``NtCreateProcess``…) and finding the
process that caused it.

For the analysis to be possible, back ends have to have access to the virtual
machines memory. This access is granted by the custom version of QEMU that Nitro
depends on. The current back ends make use of `libvmi <http://libvmi.com/>`__ to
dissect virtual machine's memory.

Process Info Objects
--------------------

As a whole, virtual machines typically produce a lot of system call events. For
practical purposes, it is often useful to concentrate on a tiny fraction of the
events that the system produces. Knowing which process caused the event is
useful for separating interesting events from the rest.

Back ends associate each system call with process that originated them. The
process information is stored in :class:`~.Process` objects. These are specific
to each back end as they contain operating system specific information. In
general, process info objects contain the process ID and the name of the binary.

System Call Argument Access
---------------------------



