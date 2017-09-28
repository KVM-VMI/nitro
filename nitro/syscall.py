class Syscall:
    __slots__ = (
        "event",
        "full_name",
        "name",
        "process",
        "args",
        "hook"
    )

    def __init__(self, event, full_name, name, process, args):
        self.event = event
        self.full_name = full_name
        self.name = name
        self.process = process
        self.args = args
        self.hook = None

    def as_dict(self):
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
