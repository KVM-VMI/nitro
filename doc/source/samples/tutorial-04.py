from nitro.nitro import Nitro
from nitro.libvmi import LibvmiError

with Nitro("Windows-VM", introspection=True) as nitro:
    self.nitro.listener.set_traps(True)
    for event in nitro.listen():
        try:
            syscall = nitro.backend.process_event(event)
        except LibvmiError:
            print("Failed to analyze event :/")
        else:
            if syscall.process.name == "notepad.exe":
                print(syscall.as_dict())
