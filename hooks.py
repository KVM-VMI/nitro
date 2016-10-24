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
        if ctxt.event.nitro_event.direction == Event.DIRECTION_ENTER:
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
            try:
                data = hook()
            except ValueError as e:
                data = "Page Fault"
            except Exception as e:
                logging.debug(e)
            try:
                logging.info('[{}][{}][{}] {}'.format(
                        self.ctxt.process.pid,
                        self.ctxt.process.name,
                        self.ctxt.syscall_name,
                        data))
            except UnicodeEncodeError:
                #logging.debug('UnicodeEncodeError')
                pass

    def enter_NtOpenFile(self):
        pid = self.ctxt.process.pid
        pobj_attr = self.ctxt.event.regs.r8
        obj = ObjectAttributes(pobj_attr, self.ctxt, self.vmi)
        return obj.PUnicodeString.Buffer

    def enter_NtOpenKey(self):
        pid = self.ctxt.process.pid
        pobj_attr = self.ctxt.event.regs.r8
        obj = ObjectAttributes(pobj_attr, self.ctxt, self.vmi)
        return obj.PUnicodeString.Buffer

    def enter_NtOpenEvent(self):
        pid = self.ctxt.process.pid
        pobj_attr = self.ctxt.event.regs.r8
        obj = ObjectAttributes(pobj_attr, self.ctxt, self.vmi)
        return obj.PUnicodeString.Buffer

    def enter_NtOpenProcess(self):
        pid = self.ctxt.process.pid
        pobj_attr = self.ctxt.event.regs.r8
        obj = ObjectAttributes(pobj_attr, self.ctxt, self.vmi)
        return obj.PUnicodeString.Buffer
