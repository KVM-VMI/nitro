# Requirements

- `genisoimage`

# Testing

This directory contains a script named `test_nitro.py` to benchmark Nitro
performance.

Running `sudo ./test_nitro.py` will do the following operations :

1. Check for every domain named `nitro_*` in `qemu:///system`
2. start the domain
3. wait for the DHCP request to get the ip address via polling on `ip neigh`
4. set nitro traps and start counting the number of syscalls
5. insert a CDROM with autorun
6. run the test command (list content under `C:\Windows\system32`)
7. repeat this procedure 3 times
8. display the average elapsed time per test

Execution output:

~~~
Testing nitro_win7x64
MAC address : 52:54:00:99:b1:ce
Flushing Arp cache
IP address : 192.168.122.225
ISO generated at /tmp/tmp5evvw3mc
Finding QEMU pid for domain nitro_win7x64
attach_vm PID = 4938
Mounting CDROM image
attach_vcpus
Detected 1 VCPUs
Counting syscalls...
set_syscall_trap True
Start listening on VCPU 0
set_syscall_trap False
Nb Syscalls : 362454
[TEST 1] Total execution time : 0:02:45.670122
...
~~~

# Building Test VMs

In the `packer-windows` directory you will find a `packer` binary and 2 templates
to build ready to test Windows VMs.

The templates apply the following modifications:

- Disable Windows Updates (to reduce noise)
- Open the WinRM service on public networks

To build a vm, run `./packer build <template.json>`.
Once the build is done, the image will be available in `packer-windows/output-qemu` directory.

# Importing VMs

To easily import the vm in libvirt, you can use the script `import_libvirt.py`,
which will do the following modifications:
- create a storage pool named `nitro` associated with a subdirectory named `images` under `tests`
- move the disk image from `output-qemu` to `images`
- set the name of the vm to `nitro_<vm_name>`
- optionnaly configure a custom QEMU binary

~~~
Usage:
  import_libvirt.py [--qemu=<path>] <qemu_image>

Options:
  -h --help         Show this screen.
  --qemu=<path>     Path to custom QEMU binary
~~~

# Custom QEMU

You will need to compile a custom QEMU from the `qemu` subdirectory which contains
already the modifications to allow a read/write access to the guest memory.
This allows `libvmi` to perform an introspection and `nitro` to analyze syscalls events.
