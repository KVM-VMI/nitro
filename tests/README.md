# Requirements

- `genisoimage`

# Testing

The tests can be run with `nose2`

A test consist of the following operations:

1. start the domain `nitro_win7x64`
2. wait for the DHCP request to get the ip address via polling on `ip neigh`
3. wait for WinRM service to be available
4. set nitro traps and start listening to syscall events
5. configure and insert a CDROM to execute a binary or a script
6. wait for WinRM service to be closed
7. stop the domain and the test

This is an example of the API used to build a test:

~~~Python
script = 'powershell -Command \"Get-ChildItem -Path C:\\windows\\system32"'
self.cdrom.configure_test(script)
cdrom_iso = self.cdrom.generate_iso()
events, exec_time, nb_syscall = self.vm_test.run(cdrom_iso)
logging.info('Test execution time {}'.format(exec_time))
~~~

use `nose2 -log-capture` to get the logging output

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
