Developing Nitro: Testing
=========================

In this chapter we take a look at how Nitro is tested and what is required for
running the tests. Testing is essential for ensuring the quality of Nitro and
for protecting us from accidental regression.

Unit Tests
----------

As a project, Nitro is highly dependent on multiple external components like the
customized version of the Linux kernel and the extended QEMU virtual machine
platform. While all this is necessary, it makes testing the project a bit more
challenging than the average Python module.

Unit tests try to break down this complexity by concentrating on individual
components and features of them. We replace the real interfaces and dependencies
with `mocked <https://en.wikipedia.org/wiki/Mock_object>`_ impostors to remove
the need for complex outside dependencies and to make the tests more
deterministic. This limits the kinds of tests we can create but is ideal for
verifying the correctness of core logic.

Because of the self-contained nature of unit tests, running the test suite is
simple. The unit test suite is located in ``tests/unittests`` directory and the
tests can be run by simply invoking the ``nose2`` test runner there.

.. literalinclude:: samples/testing-01.txt

Because of the lax requirements for the testing environment, Nitro's unit tests
are ideal for running in an automated fashion as a part of a continuous
integration pipeline.

Integration Tests
-----------------

While unit tests are useful, it is often difficult to test how the system
operates as a whole and how it interacts with a real guest operating systems.
For this reason, Nitro includes a suite of integration tests that try out the
different features in a test environment with virtual machines. The environment
enables us to automatically run test binaries inside real virtual machines and
checks that Nitro can correctly analyze their actions.

Creating a Testing VM
~~~~~~~~~~~~~~~~~~~~~

Before actual testing can take place, a virtual machine needs to be created. For
tests to be deterministic, the VM must be constructed in a way that allows us to
know exactly what gets included and what the result will be. This is to make
sure we can reliably replicate problems that might arise during testing.
Additionally, the virtual machine images we use for testing are specifically
optimized for testing purposes with unnecessary services disabled.

Nitro includes `Packer <https://www.packer.io>`_ virtual machine templates for
building the test environment. The ``tests/vm_templates`` directory includes the
``packer`` binary itself and templates for Linux and Windows testing
environments. With the templates in place, we can simply ask packer to create
the VM for us:

.. literalinclude:: samples/testing-02.txt

After the process finishes, we have to import the created VM into ``libvirt``.
This can be done automatically with the included ``import_libvirt.py`` script.
Depending on the way your ``libvirt`` installation is configured, the script
might require superuser privileges. To import the newly constructed VM run:

::

   # ./import_libvirt.py output-qemu/ubuntu1604

The import script will create a new storage pool with the name ``nitro`` at the
``tests/images`` directory and move the generated VM image there from the
``output-qemu`` directory where Packer left it. Subsequently, the script will
define a new ``libvirt`` domain for the machine and associate the image with it.
The domain is created with system ``libvirt`` instance. Finally the script will
remove the unnecessary ``output-qemu`` directory.

Running the Tests
~~~~~~~~~~~~~~~~~

Once the virtual machine is in place, we can proceed to actual testing. Nitro's
integration tests work by first restoring the testing virtual machine to a clean
state from a snapshot. After this, the test runner packages the selected test
binary into an ISO image that can be attached to the virtual machine. To run the
tests, the test runner boots up the VM, waits for it to settle, and attaches the
disc image to it. Each testing virtual machine contains special configuration
for automatically executing the attached test images. Finally, test runner
attaches Nitro to the virtual machine and monitors the execution. At the end,
each test case can check the produced execution traces for features interesting
to them.

While all this might seem complicated, all the hard work is done automatically
by the testing framework. To run the test suite, simply invoke ``nose2`` within
the ``tests`` directory. Running all the tests can be time consuming, and
therefore, it is often desirable to only run some of the tests. This can be
achieved by specifying the test case manually:

::

   $ nose2 --verbose test_linux.TestLinux.test_open

