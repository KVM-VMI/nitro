from nitro.nitro import Nitro

with Nitro("Windows-VM", introspection=True) as nitro:
    self.nitro.listener.set_traps(True)
    for event in nitro.listen():
        print(event.as_dict())
