import logging
from event import Event

class Hooks:

    def __init__(self, vmi):
        self.vmi = vmi

    def dispatch(self, ctxt):
        prefix = None
        self.ctxt = ctxt
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

    # def enter_NtOpenKey(self):
    #     logging.debug("NtOpenKey")
    #     stack = self.ctxt.event.regs.rdx
    #     pid = self.ctxt.process.pid
    #     print(pid)
    #     paddr = self.vmi.translate_kv2p(stack)
    #     print(hex(paddr))
    #     #handle = self.vmi.read_addr_va(stack, 0)
    #     #mask = self.vmi.read_addr_va(stack + 4, 0)
    #     #obj_attr = self.vmi.read_addr_va(stack + 8, 0)
    #     #logging.debug("handle = {}", hex(handle))
    #     #logging.debug("mask = {}", hex(mask))
    #     #logging.debug("obj_attr = {}", hex(obj_attr))
