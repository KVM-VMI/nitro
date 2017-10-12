class Syscall:
    """
    Class representing system call events.

    In contrast to NitroEvent events, Syscall class offers a higher-level view
    of what is happening inside the virtual machine. The class enables access to
    information about the process that created the event and makes it possible
    to access call's arguments.
    """

    __slots__ = (
        "event",
        "full_name",
        "name",
        "process",
        "args",
        "hook"
    )

    def __init__(self, event, full_name, name, process, args):
        #: Associated low-level NitroEvent
        self.event = event
        #: Full name of the systme call handler (eg. SyS_write)
        self.full_name = full_name
        #: Short "cleaned up" name of the system call handler (eg. write)
        self.name = name
        #: Process that produced the event
        self.process = process
        #: Arguments passed to the call
        self.args = args
        #: Hook associated with the event
        self.hook = None

    def as_dict(self):
        """Retrieve a dict representation of the system call event."""
        info = {
            "full_name": self.full_name,
            "name": self.name,
            "event": self.event.as_dict(),
        }
        if self.process:
            info['process'] = self.process.as_dict()
        if self.hook:
            info['hook'] = self.hook
        if self.args is not None and self.args.modified:
            info['modified'] = self.args.modified
        return info
