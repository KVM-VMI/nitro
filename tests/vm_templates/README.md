# VM templates for Nitro


# build

Use `packer` with a `var file`
~~~
$ ./packer build --var-file=<var_file.json> <template.json>
~~~

Example for `Windows 7`
~~~
$ ./packer build --var-file=windows_7_x64.json windows.json
~~~

`var files`
- `windows_7_x64.json`
- `windows_8_x64.json`
- `ubuntu_1604_x64.json`

`templates`
- `windows.json`
- `ubuntu.json`

# Import in libvirt

Use `import_libvirt.py` to import your generated `qcow` as a defined 
`libvirt` domain.

~~~
# ./import_libvirt.py output_qemu/win7x64
~~~

This script will do the following actions
1. create a `nitro` pool storage in `nitro/tests/images`
2. move the qcow to from `output-qemu` to this new pool
2. define a new domain in `qemu:///system` named `nitro_<vm_name>`
3. remove `output-qemu` directory

To specify a custom QEMU, if the `kvm-vmi` one is not installed in `/usr/bin/qemu-system-x86`, 
use the `--qemu` switch
~~~
./import_libvirt.py --qemu /home/developer/kvm-vmi/qemu/x86_64-softmmu/qemu-system-x86_64 packer-windows/output-qemu/win7x64
~~~
