"""
Backends process stream of ``NitroEvent`` objects and produce higher-level
``Systemcall`` events with operating-system-specific information such as ``Process``
that generated the event and arguments.
"""

import logging
import json
from collections import defaultdict

from nitro.event import SyscallDirection
from libvmi import LibvmiError

class Backend:
    """
    Base class for Backends. ``Backend`` provides functionality for dispatching
    hooks and keeping statistics about processed events.
    """

    __slots__ = (
        "domain",
        "libvmi",
        "hooks",
        "stats",
        "listener",
        "syscall_filtering"
    )

    def __init__(self, domain, libvmi, listener, syscall_filtering=True):
        """Create a new ``Backend``"""

        #: libvirt domain associated with the backend
        self.domain = domain
        #: handle to libvmi
        self.libvmi = libvmi
        #: ``Listener`` associated with the ``Backend``
        self.listener = listener
        #: Is system call filtering enabled for the backend
        self.syscall_filtering = syscall_filtering
        #: Event hooks
        self.hooks = {
            SyscallDirection.enter: {},
            SyscallDirection.exit: {}
        }
        #: Statistics about the backend
        self.stats = defaultdict(int)

    def dispatch_hooks(self, syscall):
        # TODO: don't dispatch if the process is None
        if syscall.process is None:
            return

        try:
            hook = self.hooks[syscall.event.direction][syscall.name]
        except KeyError:
            pass
        else:
            try:
                logging.debug('Processing hook %s - %s',
                              syscall.event.direction.name, hook.__name__)
                hook(syscall, self)
            # FIXME: There should be a way for OS specific backends to report these
            # except InconsistentMemoryError: #
            #     self.stats['memory_access_error'] += 1
            #     logging.exception('Memory access error')
            except LibvmiError:
                self.stats['libvmi_failure'] += 1
                logging.exception('VMI_FAILURE')
            # misc failures
            except ValueError:
                self.stats['misc_error'] += 1
                logging.exception('Misc error')
            except Exception:
                logging.exception('Unknown error while processing hook')
            else:
                self.stats['hooks_completed'] += 1
            finally:
                self.stats['hooks_processed'] += 1

    def define_hook(self, name, callback, direction=SyscallDirection.enter):
        """
        Register a new system call hook with the ``Backend``.
        
        :param str name: Name of the system call to hook.
        :param callable callback: Callable to call when the hook is fired.
        :param SyscallDirection direction: Should the hook fire when system call is entered or exited.
        """
        logging.info('Defining %s hook on %s', direction.name, name)
        self.hooks[direction][name] = callback

    def undefine_hook(self, name, direction=SyscallDirection.enter):
        """
        Unregister a hook.
        """
        logging.info('Removing hook on %s', name)
        self.hooks[direction].pop(name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()

    def stop(self):
        """Stop the backend"""
        logging.info(json.dumps(self.stats, indent=4))
        self.libvmi.destroy()
