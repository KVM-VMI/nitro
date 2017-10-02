Installation
============

Nitro is a complex piece of software and, unfortunatelly, requires quite a bit
of setup work to get everything up and running. Hopefully the process of
installing Nitro will eventually get simpler, but for now, this document tries
to provide enough information for you to succesfully setup the framework.
Additional instruction can be found on the projects `README
<https://github.com/KVM-VMI/nitro/blob/master/README.md>`__.

Unfortunatelly, it is not feasable to explain everything here about how to
compile and install custom kernels or how to neatly install software from
sources as these may depend on the target system in question. For this reason,
this chapter requires a certain level of technical expertise. While not
everything is explained, hopefully this chapter still contains enough pointers
for someone wishing to install the system.

Obtaining the Kernel
--------------------

The mainline Linux kernel does not currently support fine control of KVM virtual
machine execution. For providing this essential functionality, Nitro depends on
a modified version of the Linux kernel with additional functionality added to
the KVM. The sources for this custom release of Linux can be found on the
projects `Github repository <https://github.com/KVM-VMI/kvm-vmi>`__.

Setting up QEMU
---------------

Nitro uses QEMU as a hypervisor. Unfortunatelly, the upstream QEMU does not
currently provide means for efficiently accessing virtual machines memory from
the host. For this reason, Nitro requires a custom version of the QEMU
virtualization platform. Sources can be found on the projects `Github repository
<https://github.com/KVM-VMI/qemu>`__.

Getting libvmi
--------------

Libvmi library offers building blocks for virtual machine introspection. Nitro
requires a custom version of this library. You can find the sources for this
from the projects `Github repository <https://github.com/KVM-VMI/libvmi>`__.

Setting up libvirt
------------------

For setting up and managing virtual machines and their associated resources,
Nitro uses the excellent `libvirt toolkit <https://libvirt.org/>`__. Be sure to
additionally install the python bindings for the libvirt API. For Ubuntu, they
are in the ``python3-libvirt`` package.

Python Dependencies
-------------------

Aside from the core requirements outlined above, Nitro depends on a set of
Python modules that can be easily installed using ``pip`` or distribution
package manager. If you decide to install the dependencies using ``pip``,
consider using a `virtual environment
<https://docs.python.org/3/library/venv.html>`__ for separating them from the
rest of your development setup.

You can easily install these by running:

::

   pip install docopt ioctl-opt rekall cffi

Additionally, for testing, you might want to install `nose2
<https://github.com/nose-devs/nose2>`__ test framework:

::

   pip install nose2

For generating the documentation install Sphinx and the required theme:

::

   pip install sphinx sphinx_rtd_theme


Setting up Nitro for Development
--------------------------------


