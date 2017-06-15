from nitro.listener import Listener
from nitro.backends import get_backend

class Nitro:

    def __init__(self, domain, introspection=True):
        self.listener = Listener(domain)
        self.introspection = introspection
        if self.introspection:
            self.backend = get_backend(domain)

    def listen(self):
        yield from self.listener.listen()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.introspection:
            self.backend.stop()
        self.listener.stop()
