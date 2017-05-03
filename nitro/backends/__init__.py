from ..libvmi import VMIOS, Libvmi

from .linux import Linux
from .windows import Windows
from .common import Backend

BACKENDS = {
    VMIOS.LINUX: Linux,
    VMIOS.WINDOWS: Windows
}


def get_backend(domain, analyze):
    """Return backend based on libvmi configuration. If analyze if False, returns a dummy backend that does not analyze system calls. Returns None if the backend is missing"""
    libvmi = Libvmi(domain.name())
    if analyze:
        backend = BACKENDS.get(libvmi.get_ostype())
        if backend is not None:
            return backend(domain)
    else:
        return Backend(domain)
