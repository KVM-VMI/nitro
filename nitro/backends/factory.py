from libvmi import VMIOS, Libvmi
from nitro.backends.linux import LinuxBackend
from nitro.backends.windows import WindowsBackend

BACKENDS = {
    VMIOS.LINUX: LinuxBackend,
    VMIOS.WINDOWS: WindowsBackend
}

class BackendNotFoundError(Exception):
    pass

def get_backend(domain, listener, syscall_filtering):
    """
    Return a suitable backend based on guest operating system.

    :param domain: libvirt domain
    :returns: new backend instance
    :rtype: Backend
    :raises: BackendNotFoundError
    """
    libvmi = Libvmi(domain.name())
    os_type = libvmi.get_ostype()
    try:
        return BACKENDS[os_type](domain, libvmi, listener, syscall_filtering)
    except KeyError:
        raise BackendNotFoundError('Unable to find an appropritate backend for'
                                   'this OS: {}'.format(os_type))
