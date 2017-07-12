# Tests

This directory contains the test suite for Nitro, based on the `Nose2` framework.

# Requirements

- `nose2`
- `genisoimage`
- dedicated test VM (_see Building test VMs_ section)

# Setup

The tests only targets `Windows_7_x64` for now.

The test procedure expects to find a VM named `nitro_win7x64` in libvirt `qemu:///system`.

In the `vm_templates` directory you will find a `packer` binary and templates
to build ready to test Windows VMs.

Check `vm_templates/README` for detailed instructions.


# Running tests

Tests are run under the `nose2` framework. (_[documentation](http://nose2.readthedocs.io/en/latest/getting_started.html)_)

Note: If you install the debian package `python3-nose2`, the executable is named `nose2-3`.

Remember that you need a custom test VM named `nitro_win7x64` to run the tests.

## Usage

This will run all tests available in all the test files, quitely and display the overall result
~~~
$ nose2
~~~

You can ask `nose` to be a bit verbose and display which tests it is running with  `-v`
~~~
$ nose2 -v
~~~

You can also ask him to be more verbose by capturing the `logging` output, useful to debug and understand what is really happenning during the test.
~~~
$ nose2 -v --log-capture
~~~

## Running a specific test

The `Nose2` test name is `test_file.TestClass.test_name`

For example, if you want to run `test_hook_openkey` located in the `TestWindows` class inside the `test_windows.py`:

~~~
$ nose2 --log-capture test_windows.TestWindows.test_hook_openkey
~~~

## Test output

Each test which is run will create a `<test_name>` directory under `tests/`, containing a least the `test.log` logging output.

The Nitro events are also dumped there, usually in a file named `events.json`, if specified during the test.

## General test behavior

A test consists of the following operations:

1. start the domain `nitro_win7x64`
2. wait for the DHCP request to get the ip address
3. wait for WinRM service to be available (_port_ `5985`)
4. set nitro traps and start listening to syscall events
5. configure and insert a CDROM to execute a binary or a script (_this is your test configuration_)
6. wait for WinRM service to be closed
7. stop the domain and the test

# Developing new tests

A Nitro test code is composed the following steps
1. configure the CDROM to be injected
2. define the nitro callbacks
3. run Nitro and get the events
4. analyze the events and validate the test

Test code example
~~~Python
def test_01(self):
    # 1. configure the cdrom
    # a custom binary
    self.vm.cdrom.set_executable('binary_path')
    # a batch script
    script = 'dir C:\\windows\\system32'
    self.vm.cdrom.set_script(script)
    # a powershell script
    script = 'Get-ChildItem -Path C:\\windows\\system32'
    self.vm.cdrom.set_script(script, powershell=True)
    
    # 2. define your Nitro callbacks
    def enter_NtOpenFile(syscall, backend):
        logging.info('enter in NtOpenFile')
        syscall.hook = 'foobar'
        
    hooks = {
        'NtOpenFile': enter_NtOpenFile,
    }
    
    # 3. run the test and get the events
    # This will start Nitro in the background and wait for the test to be executed
    events, exec_time = self.vm.run_test(hooks=hooks)
    
    # optional: log nitro events
    logging.debug('Writing events...')
    with open('events.json', 'w') as f:
        json.dump(events, f, indent=4)
        
    # 4. analyze events and validate
    event_found = [e for e in events if e.get('hook') and e['hook'] == "foobar"]
    self.assertTrue(event_found)
~~~

## Controlling Nitro loop in the test

If you want to directly control the nitro loop by yourself, here is how to do it.

~~~Python
def test_loop(self):
    script = 'Get-ChildItem -Path C:\\windows\\system32'
    self.vm.cdrom.set_script(script, powershell=True)

    events = []
    with Backend(self.domain, True) as backend:
        backend.nitro.set_traps(True)
        stop_event = self.vm.run_test(wait=False)
        for event in backend.nitro.listen():
            syscall = backend.process_event(event)
            
            if syscall.name == "NtOpenFile":
                logging.info('NtOpenFile')
            
            events.append(syscall.info())

            if stop_event.is_set():
                break
~~~