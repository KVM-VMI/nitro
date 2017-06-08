from nitro.backends.arguments import ArgumentMap

class LinuxArgumentMap(ArgumentMap):
    def __init__(self, event, name, process, nitro):
        super().__init__(event, name, process, nitro)

    def __getitem__(self, index):
        raise NotImplementedError()

    def __setitem__(self, index, value):
        raise NotImplementedError()
