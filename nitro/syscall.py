
# FIXME:
# Maybe we should subclass this for different backends
class Syscall:
    __slots__ = (
        "event",
        "full_name",
        "name",
        "process",
        "nitro",
        "args",
        "hook"
    )

    def __init__(self, event, full_name, name, process, nitro, args):
        self.event = event
        self.full_name = full_name
        self.name = name
        self.process = process
        self.nitro = nitro
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
        modified = self.args.modified
        if modified:
            info['modified'] = modified
        return info

