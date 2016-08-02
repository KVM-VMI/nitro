import logging
from event import Event

class Hooks:

    def __init__(self, vm):
        self.vm = vm

    def dispatch(self, ctxt):
        prefix = None
        if ctxt.event.event_type == Event.KVM_NITRO_EVENT_SYSCALL:
            prefix = 'enter'
        else:
            prefix = 'exit'

        try:
            # if hook is defined
            hook = getattr(self, '{}_{}'.format(prefix, ctxt.syscall_name))
            hook()
        except AttributeError:
            # else just log syscall
            logging.debug(ctxt)

    def enter_NtClose(self):
        logging.debug("NtClose")
