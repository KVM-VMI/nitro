import logging
import re
import stat
import os
import json
from io import StringIO
from collections import defaultdict
from rekall import session
from rekall import plugins
from tempfile import NamedTemporaryFile, TemporaryDirectory


import libvirt

from nitro.event import SyscallDirection
from nitro.syscall import Syscall
from nitro.backends.windows.process import WindowsProcess
from nitro.backends.backend import Backend
from nitro.backends.windows.arguments import WindowsArgumentMap


class WindowsBackend(Backend):
    __slots__ = (
        "nb_vcpu",
        "syscall_stack",
        "sdt",
        "tasks_offset",
        "pdbase_offset",
        "processes",
        "symbols"
    )

    def __init__(self, domain, libvmi, listener, syscall_filtering=True):
        super().__init__(domain, libvmi, listener, syscall_filtering)
        vcpus_info = self.domain.vcpus()
        self.nb_vcpu = len(vcpus_info[0])

        # create on syscall stack per vcpu
        self.syscall_stack = tuple([] for _ in range(self.nb_vcpu))
        self.sdt = None
        symbols = self.get_symbols()
        self.load_symbols(symbols)
        # save symbols
        self.symbols = symbols

        # get offsets
        self.tasks_offset = self.libvmi.get_offset("win_tasks")
        self.pdbase_offset = self.libvmi.get_offset("win_pdbase")

        self.processes = {}

    def get_symbols(self):
        # we need to put the ram dump in our own directory
        # because otherwise it will be created in /tmp
        # and later owned by root
        with TemporaryDirectory() as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir) as ram_dump:
                # chmod to be r/w by everyone
                os.chmod(ram_dump.name,
                         stat.S_IRUSR | stat.S_IWUSR |
                         stat.S_IRGRP | stat.S_IWGRP |
                         stat.S_IROTH | stat.S_IWOTH)
                # take a ram dump
                logging.info('Dumping physical memory to %s', ram_dump.name)
                flags = libvirt.VIR_DUMP_MEMORY_ONLY
                dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
                self.domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
                home = os.getenv('HOME')
                # we need to make sure the directory exists otherwise rekall will complain
                # when we specify it in the profile_path
                local_cache_path = os.path.join(home, '.rekall_cache')
                try:
                    os.makedirs(local_cache_path)
                except OSError:  # already exists
                    pass

                s = session.Session(
                    filename=ram_dump.name,
                    autodetect=["rsds"],
                    logger=logging.getLogger(),
                    autodetect_build_local='none',
                    format='data',
                    profile_path=[
                        local_cache_path,
                        "http://profiles.rekall-forensic.com"
                    ])

                symbols = {}
                output = StringIO()
                s.RunPlugin("ssdt", output=output)
                symbols['syscall_table'] = json.loads(output.getvalue())
                symbols['offsets'] = self.get_offsets(s)
                return symbols

    def load_symbols(self, symbols):
        # load ssdt entries
        nt_ssdt = {'ServiceTable': {}, 'ArgumentTable': {}}
        win32k_ssdt = {'ServiceTable': {}, 'ArgumentTable': {}}
        self.sdt = [nt_ssdt, win32k_ssdt]
        cur_ssdt = None
        for e in symbols['syscall_table']:
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
                    logging.debug('Add SSDT entry [%s] -> %s', entry, full_name)


    def get_offsets(self, session):
        offsets = defaultdict(dict)

        offsets['KPROCESS'][
            'DirectoryTableBase'] = session.profile.get_obj_offset('_KPROCESS',
                                                                   'DirectoryTableBase')

        offsets['EPROCESS'][
            'ActiveProcessLinks'] = session.profile.get_obj_offset('_EPROCESS',
                                                                   'ActiveProcessLinks')

        offsets['EPROCESS']['ImageFileName'] = session.profile.get_obj_offset(
            '_EPROCESS',
            'ImageFileName')

        offsets['EPROCESS']['UniqueProcessId'] = session.profile.get_obj_offset(
            '_EPROCESS',
            'UniqueProcessId')

        offsets['EPROCESS']['InheritedFromUniqueProcessId'] = \
            session.profile.get_obj_offset('_EPROCESS',
                                           'InheritedFromUniqueProcessId')

        offsets['EPROCESS']['Wow64Process'] = \
            session.profile.get_obj_offset('_EPROCESS', 'Wow64Process')

        offsets['EPROCESS']['CreateTime'] = \
            session.profile.get_obj_offset('_EPROCESS', 'CreateTime')

        offsets['EPROCESS']['SeAuditProcessCreationInfo'] = \
            session.profile.get_obj_offset('_EPROCESS',
                                           'SeAuditProcessCreationInfo')

        offsets['SE_AUDIT_PROCESS_CREATION_INFO']['ImageFileName'] = \
            session.profile.get_obj_offset('_SE_AUDIT_PROCESS_CREATION_INFO',
                                           'ImageFileName')

        offsets['OBJECT_NAME_INFORMATION']['Name'] = \
            session.profile.get_obj_offset('_OBJECT_NAME_INFORMATION', 'Name')

        offsets['EPROCESS']['Peb'] = session.profile.get_obj_offset('_EPROCESS',
                                                                    'Peb')

        offsets['PEB']['ProcessParameters'] = \
            session.profile.get_obj_offset('_PEB', 'ProcessParameters')

        offsets['RTL_USER_PROCESS_PARAMETERS']['CommandLine'] = \
            session.profile.get_obj_offset('_RTL_USER_PROCESS_PARAMETERS',
                                           'CommandLine')

        return offsets

    def process_event(self, event):
        # invalidate libvmi cache
        self.libvmi.v2pcache_flush()
        self.libvmi.pidcache_flush()
        self.libvmi.rvacache_flush()
        self.libvmi.symcache_flush()
        # rebuild context
        cr3 = event.sregs.cr3
        # 1 find process
        process = self.associate_process(cr3)
        # 2 find syscall
        if event.direction == SyscallDirection.exit:
            try:
                syscall = self.syscall_stack[event.vcpu_nb].pop()
                # replace register values
                syscall.event = event
            except IndexError:
                # FIXME: This is ugly, names should be None
                syscall = Syscall(event, 'Unknown', 'Unknown', process, None)
        else:
            syscall_name = self.get_syscall_name(event.regs.rax)
            # build syscall
            args = WindowsArgumentMap(event, process)
            cleaned = clean_name(syscall_name)
            syscall = Syscall(event, syscall_name, cleaned, process, args)
            # push syscall to the stack to retrieve it at exit
            self.syscall_stack[event.vcpu_nb].append(syscall)
        # dispatch on the hooks
        self.dispatch_hooks(syscall)
        return syscall

    def define_hook(self, name, callback, direction=SyscallDirection.enter):
        super().define_hook(name, callback, direction)
        if self.syscall_filtering:
            self.add_syscall_filter(name)

    def undefine_hook(self, name, direction=SyscallDirection.enter):
        super().undefine_hook(name, direction)
        if self.syscall_filtering:
            self.remove_syscall_filter(name)

    def find_syscall_nb(self, syscall_name):
        for ssdt in self.sdt:
            for syscall_nb, full_name in ssdt['ServiceTable'].items():
                if re.match(r'^.*{}$'.format(syscall_name), full_name):
                    return syscall_nb
        return None

    def associate_process(self, cr3):
        if cr3 in self.processes:
            p = self.processes[cr3]
        else:
            p = self.find_eprocess(cr3)
            # index by cr3 or pid
            # a callback might want to search by pid
            self.processes[cr3] = p
            self.processes[p.pid] = p
        return p

    def find_eprocess(self, cr3):
        # read PsActiveProcessHead list_entry
        ps_head = self.libvmi.translate_ksym2v('PsActiveProcessHead')
        flink = self.libvmi.read_addr_ksym('PsActiveProcessHead')

        while flink != ps_head:
            # get start of EProcess
            start_eproc = flink - self.symbols['offsets']['EPROCESS'][
                'ActiveProcessLinks']
            # move to start of DirectoryTableBase
            directory_table_base_off = start_eproc + \
                                       self.symbols['offsets']['KPROCESS'][
                                           'DirectoryTableBase']
            # read directory_table_base
            directory_table_base = self.libvmi.read_addr_va(
                directory_table_base_off, 0)
            # compare to our cr3
            if cr3 == directory_table_base:
                return WindowsProcess(self.libvmi, cr3, start_eproc,
                                      self.symbols)
            # read new flink
            flink = self.libvmi.read_addr_va(flink, 0)
        raise RuntimeError('Process not found')

    def get_syscall_name(self, rax):
        ssn = rax & 0xFFF
        idx = (rax & 0x3000) >> 12
        try:
            syscall_name = self.sdt[idx]['ServiceTable'][ssn]
        except (KeyError, IndexError):
            # this code should not be reached,
            # because there is only 2 SSDT's defined in Windows (Nt and Win32k)
            # the 2 others are NULL
            syscall_name = 'Table{}!Unknown'.format(idx)
        return syscall_name

    def add_syscall_filter(self, syscall_name):
        syscall_nb = self.find_syscall_nb(syscall_name)
        if syscall_nb is None:
            raise RuntimeError(
                'Unable to find syscall number for %s' % syscall_name)
        self.listener.add_syscall_filter(syscall_nb)

    def remove_syscall_filter(self, syscall_name):
        syscall_nb = self.find_syscall_nb(syscall_name)
        if syscall_nb is None:
            raise RuntimeError(
                'Unable to find syscall number for %s' % syscall_name)
        self.listener.remove_syscall_filter(syscall_nb)


def clean_name(name):
    return name.split('!')[-1]
