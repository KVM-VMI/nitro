from nitro.backends.arguments import ArgumentMap

class LinuxArgumentMap(ArgumentMap):
    def __getitem__(self, index):
        raise NotImplementedError()

    def __setitem__(self, index, value):
        raise NotImplementedError()
