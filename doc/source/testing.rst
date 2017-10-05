Developing Nitro: Testing
=========================

In this chapter we take a look at how Nitro is tested and what is required for
running the tests. Testing is essential for ensuring the quality of Nitro and
for protecting us from accidental regression.

Unit Tests
----------

As a project, Nitro is highly dependent on multiple external components like the
customized version of the Linux kernel and the extended QEMU hypervisor. While
all this is necessary, it makes testing the project a bit more challenging than
the average Python module.

Unit tests try to break down this complexity by concentrating on individual
components and features of them. We replace the real interfaces and dependencies
with `mocked <https://en.wikipedia.org/wiki/Mock_object>`_ impostors to remove
the need for complex outside dependencies and to make the tests more
deterministic. This limits the kinds of tests we can create but is ideal for
verifying the correctness of core logic.

Because of the self-contained nature of unit tests, running the test suite is
simple. The unit test suite is located in ``tests/unittests`` directory and the
tests can be run by simply invoking the ``nose2`` test runner there.

Because of the lax requirements for the testing environment, Nitro's unit tests
are ideal for running in an automated fashion as a part of a continuous
integration pipeline.

Integration Tests
-----------------

While unit tests are useful, it is often difficult to test how the system acts
as a whole and interacts with a real guest operating systems. For these reasons,
Nitro includes a suite of integration tests that try out the different features
in a test environment with virtual machines. In this environment, we can run
automatically run test binaries inside the virtual machines and checks that
Nitro can correctly see their behavior.


