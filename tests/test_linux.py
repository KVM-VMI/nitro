import unittest
from layers import LinuxVMLayer

class TestLinux(unittest.TestCase):
    layer = LinuxVMLayer

    # TODO: Implement
    def test_hook_open(self):
        binary_path = os.path.join(self.script_dir, "linux_binaries", "open")
        self.vm.cdrom.set_executable(binary_path)

        def enter_open(syscall):
            path = syscall.args[0]
            flags = syscall.args[1]
        
        hooks = {
            "open": enter_open
        }

        events, exec_time = self.vm.run_test(hooks=hooks)

