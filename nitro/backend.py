import logging
import re
import os
import stat
import libvirt
import subprocess
import shutil
import json
from tempfile import NamedTemporaryFile, TemporaryDirectory
from nitro.event import SyscallDirection, SyscallType
from nitro.libvmi import Libvmi
from nitro.win_types import ObjectAttributes

GETSYMBOLS_SCRIPT = 'symbols.py'


class Process:

    def __init__(self, cr3, start_eproc, name, pid):
        self.cr3 = cr3
        self.start_eproc = start_eproc
        self.name = name
        self.pid = pid

    def info(self):
        info = {}
        info['name'] = self.name
        info['pid'] = self.pid
        return info


class Syscall:

    ARGUMENT_TABLE = {
        'NtOpenKey': 3,
    }

    def __init__(self, event, name, process, vmi):
        self.event = event
        self.full_name = name
        # clean rekall syscall name
        # full_name is 'nt!NtOpenFile'
        # name will be NtOpenFile
        *rest, self.name = self.full_name.split('!')
        self.process = process
        # args and return value
        if self.event.direction == SyscallDirection.exit:
            # ret value
            self.retvalue = self.event.regs.rax
        else:
            self.args = self.collect_args()
        self.vmi = vmi
        self.decoded = None

    def info(self):
        info = {}
        info['name'] = self.name
        info['event'] = self.event.info()
        if self.process:
            info['process'] = self.process.info()
        if self.event.direction == SyscallDirection.exit:
            info['retvalue'] = self.retvalue
        else:
            info['args'] = self.args
        if self.decoded:
            info['decoded'] = self.decoded
        return info

    def collect_args(self):
        try:
            # if syscall is defined in hardcoded argument table
            count = self.ARGUMENT_TABLE[self.name]

            # collect args
            if self.event.type == SyscallType.syscall:
                # assume Windows here
                # convention is first 4 args in rcx,rdx,r8,r9
                # rest on stack
                args = [self.event.regs.rcx,
                        self.event.regs.rdx,
                        self.event.regs.r8,
                        self.event.regs.r9, ]
                if count > 4:
                    raise RuntimeError('collecting more than 4 arguments is not implemented')
                return args[:count]
            else:
                # sysenter is not handled
                raise RuntimeError('collecting SYSENTER arguments is not implemented')
        except KeyError:
            return []

    def dispatch(self):
        # don't dispatch to the hooks if process is None
        # TODO
        if self.process is None:
            return
        prefix = 'enter' if self.event.direction == SyscallDirection.enter else 'exit'

        try:
            # if hook is defined
            hook_name = '{}_{}'.format(prefix, self.name)
            hook = getattr(self, hook_name)
        except AttributeError:
            # hook not defined
            pass
        else:
            try:
                logging.debug('Hook {}'.format(hook_name))
                hook(*self.args)
            except ValueError:
                # log page fault
                logging.debug('Error while processing hook')

    # hooks defined here
    def enter_NtOpenKey(self, KeyHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtCreateKey(self, KeyHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtOpenEvent(self, EventHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtCreateEvent(self, EventHandle, DesiredAccess, object_attributes):
        if object_attributes:
            obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
            buffer = obj.PUnicodeString.Buffer
            self.decoded = buffer

    def enter_NtOpenProcess(self, ProcessHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtCreateProcess(self, ProcessHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtOpenFile(self, EventHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtCreateFile(self, EventHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtOpenMutant(self, EventHandle, DesiredAccess, object_attributes):
        obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
        buffer = obj.PUnicodeString.Buffer
        self.decoded = buffer

    def enter_NtCreateMutant(self, EventHandle, DesiredAccess, object_attributes):
        if object_attributes:
            obj = ObjectAttributes(object_attributes, self.process.pid, self.vmi)
            buffer = obj.PUnicodeString.Buffer
            self.decoded = buffer


class Backend:

    def __init__(self, domain):
        self.domain = domain
        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])
        # create on syscall stack per vcpu
        self.syscall_stack = {}
        for vcpu_nb in range(self.nb_vcpu):
            self.syscall_stack[vcpu_nb] = []
        self.sdt = None
        self.load_symbols()
        # run libvmi helper subprocess
        self.libvmi = Libvmi(domain.name())
        self.processes = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def stop(self):
        logging.info('Libvmi failures {}'.format(self.libvmi.failures))
        self.libvmi.destroy()

    def load_symbols(self):
        # we need to put the ram dump in our own directory
        # because otherwise it will be created in /tmp
        # and later owned by root
        with TemporaryDirectory() as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir) as ram_dump:
                # chmod to be r/w by everyone
                os.chmod(ram_dump.name, stat.S_IRUSR | stat.S_IWUSR |
                                        stat.S_IRGRP | stat.S_IWGRP |
                                        stat.S_IROTH | stat.S_IWOTH)
                # take a ram dump
                logging.info('Dumping physical memory to {}'.format(ram_dump.name))
                flags = libvirt.VIR_DUMP_MEMORY_ONLY
                dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
                self.domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
                # build symbols.py absolute path
                script_dir = os.path.dirname(os.path.realpath(__file__))
                symbols_script_path = os.path.join(script_dir, GETSYMBOLS_SCRIPT)
                # call rekall on ram dump
                logging.info('Extracting symbols with Rekall')
                python2 = shutil.which('python2')
                symbols_process = [python2, symbols_script_path, ram_dump.name]
                output = subprocess.check_output(symbols_process)
        logging.info('Loading symbols')
        # load output as json
        jdata = json.loads(output.decode('utf-8'))
        # load ssdt entries
        nt_ssdt = {'ServiceTable' : {}, 'ArgumentTable' : {}}
        win32k_ssdt = {'ServiceTable' : {}, 'ArgumentTable' : {}}
        self.sdt = [nt_ssdt, win32k_ssdt]
        cur_ssdt = None
        for e in jdata:
            if isinstance(e, list) and e[0] == 'r':
                if e[1]["divider"] is not None:
                    # new table
                    m = re.match(r'Table ([0-9]) @ .*', e[1]["divider"])
                    idx = int(m.group(1))
                    cur_ssdt = self.sdt[idx]['ServiceTable']
                else:
                    entry = e[1]["entry"]
                    full_name = e[1]["symbol"]["symbol"]
                    # add entry  to our current ssdt
                    cur_ssdt[entry] = full_name
                    logging.debug('Add SSDT entry [{}] -> {}'.format(entry, full_name))

    def process_event(self, event):
        cr3 = event.sregs.cr3
        process = self.associate_process(cr3)
        if event.direction == SyscallDirection.exit:
            try:
                syscall_name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                syscall_name = 'Unknown'
        else:
            syscall_name = self.get_syscall_name(event.regs.rax)
            # push them to the stack
            self.syscall_stack[event.vcpu_nb].append(syscall_name)
        syscall = Syscall(event, syscall_name, process, self.libvmi)
        # dispatch on the hooks
        syscall.dispatch()
        return syscall

    def associate_process(self, cr3):
        p = None
        try:
            p = self.processes[cr3]
        except KeyError:
            p = self.find_eprocess(cr3)
            self.processes[cr3] = p
        return p

    def find_eprocess(self, cr3):
        # read PsActiveProcessHead list_entry
        ps_head = self.libvmi.translate_ksym2v('PsActiveProcessHead')
        flink = self.libvmi.read_addr_ksym('PsActiveProcessHead')

        while flink != ps_head:
            # get start of EProcess
            start_eproc = flink - self.libvmi.get_offset('win_tasks')
            # move to start of DirectoryTableBase
            directory_table_base_off = start_eproc + self.libvmi.get_offset('win_pdbase')
            # read directory_table_base
            directory_table_base = self.libvmi.read_addr_va(directory_table_base_off, 0)
            # compare to our cr3
            if cr3 == directory_table_base:
                # get name
                image_file_name_off = start_eproc + self.libvmi.get_offset('win_pname')
                image_file_name = self.libvmi.read_str_va(image_file_name_off, 0)
                # get pid
                unique_processid_off = start_eproc + self.libvmi.get_offset('win_pid')
                pid = self.libvmi.read_addr_va(unique_processid_off, 0)
                eprocess = Process(cr3, start_eproc, image_file_name, pid)
                return eprocess

            # read new flink
            flink = self.libvmi.read_addr_va(flink, 0)
        return None

    def get_syscall_name(self, rax):
        ssn = rax & 0xFFF
        idx = (rax & 0x3000) >> 12
        try:
            syscall_name = self.sdt[idx]['ServiceTable'][ssn]
        except (KeyError, IndexError):
            syscall_name = 'Table{}!Unknown'.format(idx)
        return syscall_name
