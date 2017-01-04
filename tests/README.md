# Testing

This directory contains a script named `test_nitro.py` to benchmark Nitro
performance.

Running `sudo ./test_nitro.py` will do the following operations :

1. Check for every domain named `nitro_*` in `qemu:///system`
2. start the domain
3. wait for the DHCP request to get the ip address via polling on `ip neigh`
4. test the WinRM service by sending an `ipconfig` command using credentials `vagrant:vagrant`
5. set nitro traps and start counting the number of syscalls
6. run a test command in a graphic powershell (currently, listing content under `system32`)
7. stop nitro
8. display results and elapsed time for the test

limitations:
- arch must be `x64`
- only 1 VCPU allowed

Execution output:

~~~
Testing nitro_win7x64
MAC address : 52:54:00:a3:92:b6
IP address : 192.168.122.71
Establishing a WinRM session
Running test command
Loading libnitro.so
Suspending the Guest
Initializing KVM
Attaching to the VM
Attaching to VCPUs
Setting Traps
Resuming the Guest
Counting syscalls...
Total execution time 0:02:04.146711
Suspending the Guest
Unsetting Traps
Closing KVM
Resuming the Guest
Nb Syscalls : 514502
Waiting for shutdown
~~~

# Building Test VMs

In the `packer-windows` directory you will find a `packer` binary and 2 templates
to build ready to test Windows VMs.

The templates apply the following modifications:

- Disable Windows Updates (to reduce noise)
- Set WinRM service to start as soon as possible (no delay)
- Open the WinRM service on public networks
- Upload _SysInternals_ `pstools` in `C:`, to run application in user desktop

To build a vm, run `./packer build <template.json>`.
Once the build is done, the image will be available in `packer-windows/output-qemu` directory.

# Importing VMs

To easily import the vm in libvirt, you can use the script `import_libvirt.py`,
which will create a storage pool named `nitro` and move the vm disk image
in an `images` directory.

Also, it will take care of setting the name of the vm to `nitro_<vm_name>`,
and configure the emulator to `kvm-vmi/qemu/x86_64-softmmu/qemu-system-x86_64`,
which is a fork of QEMU already patched with libvmi memory access modifications.

Don't forget to build QEMU. (`./configure --target-list=x86-64-softmmu`)
