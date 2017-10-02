Introduction
============

Nitro is flexible framework for seeing inside virtual machines. It provides
users with a stream of events about what the machine is doing and allows the
user to perform arbitrary inside the virtual machine. Even better, all this is
done in a way that is completely transparent to the virtual machine in question.

On a more technical level, Nitro is a virtual machine introspection system that,
through the use of clever kernel-level functionality, allows the host system to
pause virtual machine execution when system calls happen. While the virtual
machine execution is paused, Nitro carefully dissects critical operating system
data structures from its memory to understand the state of the system: what the
system was doing when the system call took place. All this information is then
passed to the user who can decide what to do with it. For example, the user
might want to extract further information from the virtual machine or perform
additional analysis that is specific to their use case or simply save the
gathered data into a database.

Why you might want to consider Nitro
------------------------------------

You might want to use Nitro when you need to have a low-level view of what your
systems are doing. While Nitro aims to provide a lot of higher-level information
on the system's state, at the most basic level Nitro offers you with tools for
inspecting (and altering) virtual machine's CPU state and contents of its
memory. If you are interested in what exactly the system is doing and want a
comprehensive view of the entire machine, Nitro might be for you.

Alternatively, you might already have system for monitoring your virtual
machines but you are concerned about how trustworthy the reported monitoring
information is. Maybe you have reasons to believe that something is altering the
data your monitoring probes collect. As Nitro resides entirely outside the
bounds of the virtual machine it monitors, it is well protected against attacks
that might want to alter the information it collects.

Or maybe you need a monitoring system that is transparent to the virtual
machines, a system where the VM does not even know it is being monitored. For
example, it is common for malware to try to actively detect if they are being
monitored and change their behavior if they believe they are being watched.
Maybe you do not want to or cannot alter the virtual machines but still want to
be able to have some idea about what is going inside of them. Nitro can help you
here.

It is also possible that you want to ensure that your software operates
correctly whatever happens. Nitro aims to help you there by providing you with
the tools for simulating abnormal system behavior. For example, how do you test
your software for hardware failures or uncommon system call return values that
almost never happen. Traditionally, bugs related to these things have been hard
to replicate and fix. One of Nitro's goals is to make this feasible by providing
tools for faking strange, uncommon, events.

State of the Project
--------------------

Nitro is still under heavy development and things are bound to change and evolve
as the project progresses. While the core aspects of Nitro are in place, many of
the finer features are still shaping up. APIs are likely to change as we iterate
the design to find the best possible form for Nitro.
