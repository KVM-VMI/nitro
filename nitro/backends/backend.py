import logging
import json
from collections import defaultdict

from nitro.event import SyscallDirection, SyscallType

class Backend:
    __slots__ = (
        "domain",
        "libvmi",
        "hooks",
        "stats",
        "listener"
    )

    def __init__(self, domain, listener, libvmi):
        self.domain = domain
        self.listener = listener
        self.libvmi = libvmi
        self.hooks = {
            SyscallDirection.enter: {},
            SyscallDirection.exit: {}
        }
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
                logging.debug('Processing hook %s - %s', syscall.event.direction.name, hook.__name__)
                hook(syscall)
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
        logging.info('Defining hook on {}'.format(name))
        self.hooks[direction][name] = callback

    def undefine_hook(self, name, direction=SyscallDirection.enter):
        logging.info('Removing hook on {}'.format(name))
        self.hooks[direction].pop(name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()

    def stop(self):
        logging.info(json.dumps(self.stats, indent=4))
        self.libvmi.destroy()
        self.listener.stop()
