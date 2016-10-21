import sys
import time
import logging
import struct


from event import Event
from win_types import ObjectAttributes

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
        except AttributeError:
            # else just log syscall
            #logging.debug(ctxt)
            pass
        else:
            hook()

    def enter_NtOpenFile(self):
        logging.debug("NtOpenFile")
        pid = self.ctxt.process.pid
        handle = self.ctxt.event.regs.rcx
        access_mask = self.ctxt.event.regs.rdx
        pobj_attr = self.ctxt.event.regs.r8
        logging.debug('pid : {}'.format(pid))
        logging.debug('handle : {}'.format(hex(handle)))
        logging.debug('access mask : {}'.format(hex(access_mask)))
        logging.debug('pobj_attr : {}'.format(hex(pobj_attr)))
        obj = ObjectAttributes(pobj_attr, self.ctxt, self.vmi)
