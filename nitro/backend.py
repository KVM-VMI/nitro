import logging
import re
import os
import stat
import libvirt
import subprocess
import shutil
import json
import struct
from collections import defaultdict
from tempfile import NamedTemporaryFile, TemporaryDirectory

from nitro.nitro import Nitro
from nitro.event import SyscallDirection, SyscallType
from nitro.libvmi import Libvmi, LibvmiError
from nitro.process import Process
from nitro.win_types import InconsistentMemoryError
from enum import Enum

GETSYMBOLS_SCRIPT = 'symbols.py'

class SyscallArgumentType(Enum):
    register = 0
    memory = 1

class Syscall:

    __slots__ = (
        'event',
        'full_name',
        'name',
        'process',
        'hook',
        'nitro',
        'args_convention',
    )

    CONVENTION = {
        SyscallType.syscall: [
            (SyscallArgumentType.register, 'rcx'),
            (SyscallArgumentType.register, 'rdx'),
            (SyscallArgumentType.register, 'r8'),
            (SyscallArgumentType.register, 'r9'),
            (SyscallArgumentType.memory, '0'),
            (SyscallArgumentType.memory, '1'),
            (SyscallArgumentType.memory, '2'),
            (SyscallArgumentType.memory, '3'),
            (SyscallArgumentType.memory, '4'),
            (SyscallArgumentType.memory, '5'),
            (SyscallArgumentType.memory, '6'),
        ],
    }

    def __init__(self, event, name, process, nitro):
        self.event = event
        self.full_name = name
        # clean rekall syscall name
        # full_name is 'nt!NtOpenFile'
        # name will be NtOpenFile
        *rest, self.name = self.full_name.split('!')
        self.process = process
        self.nitro = nitro
        self.args_convention = {}
        self.hook = None

    def info(self):
        info = {}
        info['name'] = self.name
        info['event'] = self.event.info()
        if self.process:
            info['process'] = self.process.info()
        if self.hook:
            # user added information, if any hook has been set
            info['hook'] = self.hook
        return info

    def define_arguments(self, *args):
        # check if exit
        if self.event.direction == SyscallDirection.exit:
            raise RuntimeError('You cannot define syscall arguments on the exit direction')

        try:
            convention = self.CONVENTION[self.event.type]
        except KeyError:
            raise RuntimeError('Syscall convention undefined')
        # for each argument, associate the convention
        for i, arg_name in enumerate(args):
            try:
                self.args_convention[arg_name] = convention[i]
            except IndexError:
                raise RuntimeError('Too much arguments')

    def __getitem__(self, arg_name):
        type, opaque = self.args_convention[arg_name]
        if type == SyscallArgumentType.register:
            try:
                value = getattr(self.event.regs, opaque)
            except AttributeError:
                raise RuntimeError('Unknown register')
        else:
            # memory
            reg, position = opaque
            format = 'P'
            size = struct.calcsize(format)
            try:
                addr = getattr(self.event.regs, reg) + (position * size)
            except AttributeError:
                raise RuntimeError('Unknown register')
            value, *rest = struct.unpack(self.process.read_memory(addr, size))
        return value

    def __setitem__(self, arg_name, value):
        type, opaque = self.args_convention[arg_name]
        if type == SyscallArgumentType.register:
            try:
                setattr(self.event.regs, opaque, value)
            except AttributeError:
                raise RuntimeError('Unknwon register')
            else:
                self.nitro.vcpus_io[self.event.vcpu_nb].set_regs(self.event.regs)
        else:
            # memory
            reg, position = opaque
            format = 'P'
            size = struct.calcsize(format)
            try:
                addr = getattr(self.event.regs, reg) + (position * size)
            except AttributeError:
                raise RuntimeError('Unkown register')
            buffer = struct.pack(format, value)
            self.process.write_memory(addr, buffer)


class Backend:

    __slots__ = (
        'domain',
        'nb_vcpu',
        'syscall_stack',
        'sdt',
        'libvmi',
        'processes',
        'hooks',
        'stats',
        'nitro',
        'analyze'
    )

    def __init__(self, domain, analyze=False):
        self.domain = domain
        self.analyze = analyze
        # init Nitro
        self.nitro = Nitro(self.domain)
        if analyze:
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
            self.hooks = {
                SyscallDirection.enter: {},
                SyscallDirection.exit: {}
            }
            self.stats = defaultdict(int)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def stop(self):
        logging.info(json.dumps(self.stats, indent=4))
        if self.analyze:
            self.libvmi.destroy()
        self.nitro.stop()

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
        if not self.analyze:
            raise RuntimeError('Syscall analyzing is disabled in the backend')
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
                syscall_name = self.syscall_stack[event.vcpu_nb].pop()
            except IndexError:
                syscall_name = 'Unknown'
        else:
            syscall_name = self.get_syscall_name(event.regs.rax)
            # push them to the stack
            self.syscall_stack[event.vcpu_nb].append(syscall_name)
        syscall = Syscall(event, syscall_name, process, self.nitro)
        # dispatch on the hooks
        self.dispatch_hooks(syscall)
        return syscall

    def dispatch_hooks(self, syscall):
        try:
            hook = self.hooks[syscall.event.direction][syscall.name]
        except KeyError:
            pass
        else:
            try:
                logging.debug('Processing hook {} - {}'.format(syscall.event.direction.name, hook.__name__))
                hook(self, syscall)
            except InconsistentMemoryError:
                self.stats['memory_access_error'] += 1
                logging.exception('Memory access error')
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
                eprocess = Process(cr3, start_eproc, image_file_name, pid, self.libvmi)
                return eprocess

            # read new flink
            flink = self.libvmi.read_addr_va(flink, 0)
        raise RuntimeError('Process not found')

    def get_syscall_name(self, rax):
        ssn = rax & 0xFFF
        idx = (rax & 0x3000) >> 12
        try:
            syscall_name = self.sdt[idx]['ServiceTable'][ssn]
        except (KeyError, IndexError):
            # this code should not be reached, because there is only 2 SSDT's defined in Windows (Nt and Win32k)
            # the 2 others are NULL
            syscall_name = 'Table{}!Unknown'.format(idx)
        return syscall_name
