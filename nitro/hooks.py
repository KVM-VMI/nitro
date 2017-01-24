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
            logging.debug(ctxt)
        else:
            try:
                data = hook()
            except ValueError as e:
                data = "Page Fault"
            finally:
                logging.info('[{}][{}][{}] {}'.format(
                        self.ctxt.process.pid,
                        self.ctxt.process.name,
                        self.ctxt.syscall_name,
                        data))

    def collect_args(self, nb):
        if self.ctxt.event.nitro_event.direction == Event.DIRECTION_EXIT:
            return [self.ctxt.event.regs.rax]
        else:
            if self.ctxt.event.nitro_event.type == Event.TYPE_SYSCALL:
                # assume Windows here
                # convention is first 4 args in rcx,rdx,r8,r9
                # rest on stack
                args = [self.ctxt.event.regs.rcx,
                        self.ctxt.event.regs.rdx,
                        self.ctxt.event.regs.r8,
                        self.ctxt.event.regs.r9,
                        ]
                #if nb > 4: TODO
                return args
            else:
                # SYSENTER
                # read args on stack from rdx
                # TODO
                pass

#     def enter_NtOpenFile(self):
#         pid = self.ctxt.process.pid
#         file_handle,desired_access,obj_attributes,io_status_block = self.collect_args(4)
#         obj = ObjectAttributes(obj_attributes, self.ctxt, self.vmi)
#         return obj.PUnicodeString.Buffer
# 
#     def enter_NtOpenKey(self):
#         pid = self.ctxt.process.pid
#         key_handle,desired_access,obj_attributes = self.collect_args(3)
#         obj = ObjectAttributes(obj_attributes, self.ctxt, self.vmi)
#         return obj.PUnicodeString.Buffer
# 
#     def enter_NtOpenEvent(self):
#         pid = self.ctxt.process.pid
#         event_handle,desired_access,obj_attributes = self.collect_args(3)
#         obj = ObjectAttributes(obj_attributes, self.ctxt, self.vmi)
#         return obj.PUnicodeString.Buffer
# 
#     def enter_NtOpenProcess(self):
#         pid = self.ctxt.process.pid
#         process_handle,desired_access,obj_attributes,client_id = self.collect_args(4)
#         obj = ObjectAttributes(obj_attributes, self.ctxt, self.vmi)
#         return obj.PUnicodeString.Buffer
# 
# 
