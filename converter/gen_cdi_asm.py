import __init__

import funct_cfg
import link_tables

import copy
import random
import operator
import asm_parsing
import string
import subprocess
import sys
import re
import os
import struct

import obj_parse

from common.eprint import eprint
from common.eprint import vprint
from common.eprint import vvprint
from cdi_abort import cdi_abort

# CDI Label Conventions
###########################
# Labels are used to coordinate the jumps needed for returns and indirect calls. Labels 
# are also used to designate SLT entries, RLT entries, and even relocations. What
# follows is a general format for CDI labels. '||' is the concatenation symbol
#
#   _CDI || [deletable] || _ || [type] || _ || [type dependent data (tdd)]
#
# The second field [deletable] is filled with an 'X' if the symbol is unneeded
# at load time. [type] specifies what purpose the label is used for.
#
#  Type    | Label purpose
#  --------+------------
#  FROM    | Used to coordinate return sleds and indirect call sleds. A sled label's
#          | multiplicity is used to differentiate between other call/returns from the 
#          | same two functions. Calls with higher VMAs have higher multiplicities
#          | [tdd] := [called funct's uniq_label] || _TO_ || [return funct's uniq_label] || _ || [multiplicity]
#          |
#  PLT     | Like FROM but it's used to coordinate RLT sleds and how they return to
#          | after calls into the PLT.
#          | [tdd] := [PLT symbol] || _TO_ || [return funct's uniq_label] || _ || [multiplicity]
#          |
#  F       | A global version of a function symbol. Used to call/jump from other asm units
#          | [tdd] := [function's uniq_label]
#          |
#  RLT     | Marks an RLT entry. These labels are needed for the CDI loader
#          | [tdd] := [the associated shared library symbol] at return sites
#          |
#  RREL32  | A relocation request to fill the 4 bytes before this symbol with a
#          | 32 bit signed offset from this symbol to the symbol in [tdd]. This
#          | is needed to deal with position independent code generation. The symbol
#          | in [tdd] is prefixed with a dummy value to allow multiple relocations
#          | with reference to the same symbol
#          | [tdd] := [dummy_value] || _ || [symbol to relocate against]
#          |
#  RREL32P | Like RREL32 but an additional prefix is written before the signed
#          | offset. The prefix is written in hex, and data is overwritten n + 4
#          | before this symbol where n is the size of the prefix in bytes. This 
#          | is useful to write opcodes in addition to a signed offset
#          | [tdd] := [prefix] || _ || [dummy_value] || _ || [symbol to relocate against]
#          |
#  SLED    | Used to store sled specific debug information. 
#          | [tdd] := [a unique sled id]
#          |
#  RET     | Placed right before the  jmp to _CDI_abort in a return sled
#          | The jmp will be overwritten  to a point to an inter-shared-library 
#          | function pointer return sled if there are fptrs with a matching type
#          | The multiplicity starts at 0 and is incremented for each return from
#          | the enclosing function
#          | [tdd] := [the enclosing funct's uniq_label] || _ || [multiplicity]
#          |
#  FPTR    | Placed right before the  jmp to _CDI_abort in an indirect call site
#          | The jmp will be overwritten  to a point to an inter-shared-library 
#          | function pointer call sled if there are fptrs with a matching type
#          | The multiplicity starts at 0 and is incremented for each indirect 
#          | call in the enclosing function
#          | [tdd] := [the enclosing funct's uniq_label] || _ || [multiplicity]
#          |
#  TRAM    | Marks an entry in the trampoline table
#          | [tdd for return tram] := R_ || [uniq_label of funct]
#          | [tdd for call   tram] := C_ || [fptype]
#          | 
#  --------+------------
#
# Special labels:
#   _CDI_tramtab: specifies the beginning of the trampoline tables. The SLT
#                  tramtab comes first, then the function pointer tramtab
#   _CDI_callback_sled: specifies the beginning of the shared library callback sled
#   _CDI_abort: points to a function that prints out sled debug info and exits

STARTUP_FUNCTIONS = [                                                              
        'start_c',                                                                 
        '__libc_start_main',                                                       
        'libc_start_main',                                                         
        '__init_libc',                                                             
        'static_init_tls',                                                         
        '__copy_tls',                                                              
        '__init_tp',                                                               
        '__set_thread_area',                                                       
        'dummy1',                                                                  
        '__libc_start_init',                                                       
        'libc_start_init',                                                         
        '_init',                                                                   
        'frame_dummy',                                                             
        'register_tm_clones',                                                      
        '__libc_csu_init'  # GLIBC only                                            
]                                                                                  
CLEANUP_FUNCTIONS = [                                                              
        'exit',                                                                    
        'dummy',                                                                   
        '__libc_exit_fini',                                                        
        'libc_exit_fini',                                                          
        '__do_global_dtors_aux',                                                   
        'deregister_tm_clones',                                                    
        '_fini',                                                                   
        '__libc_csu_fini' # GLIBC only                                             
]                       
WHITELIST = STARTUP_FUNCTIONS + CLEANUP_FUNCTIONS                                  

FP_WHITELIST = [
        'main'
]


def gen_cdi_asm(cfg, asm_file_descrs, plt_manager, options):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    sled_id_faucet = funct_cfg.SledIdFaucet()
    link_tables.write_linkage_tables.done = False

    label_interceptor = FunctLabelInterceptor(cfg)

    cfg.print_uniq_labels()
    cfg.print_aliases()

    for descr in asm_file_descrs:
        asm_parsing.DwarfSourceLoc.wipe_filename_mapping()
        dwarf_loc = asm_parsing.DwarfSourceLoc()
        asm_src = open(descr.filename, 'r')
        asm_dest = open(cdi_asm_name(descr.filename), 'w')
        descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
        functs = sorted(descr_functs, key=operator.attrgetter('asm_line_num'))
        abort_data = [] # used for aborting from sleds

        asm_line_num = 1
        for funct in functs:
            num_lines_to_write = funct.asm_line_num - asm_line_num
            write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc, label_interceptor)
            asm_line_num = funct.asm_line_num

            # unique labels are always global so that even static functions
            # can be reached from anywhere with sleds (Function pointers can
            # point to ANY function with the same signature, even static 
            # functions in a different translation unit). We do relocations 
            # ourselves for shared libraries. In that case, they do not need
            # to be global, because the linker cannot complain
            if not options['--shared-library']:
                asm_dest.write('.globl\t"_CDIX_F_{}"\n'.format(fix_label(funct.uniq_label)))
            asm_dest.write('"_CDIX_F_{}":\n'.format(fix_label(funct.uniq_label)))

            funct.label_fixed_count = dict()
            for site in funct.sites:
                num_lines_to_write = site.asm_line_num - asm_line_num
                write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc, label_interceptor)

                line_to_fix = asm_src.readline()
                asm_line_num = site.asm_line_num + 1
                
                convert_to_cdi(site, funct, line_to_fix, asm_dest, cfg,
                        sled_id_faucet, abort_data, dwarf_loc, options)

        # write the rest of the normal asm lines over, including the linkage
        # tables but only once. Write sled abort info in the debug section
        stack_section_decl_matcher = re.compile(r'^\s*\.section\s+\.note\.GNU-stack,')
        debug_section_matcher = re.compile(r'^\s*\.section\s+\.debug_info.+')

        stack_section_decl = ''
        src_line = asm_src.readline()
        while src_line:
            if debug_section_matcher.match(src_line):
                # while we're at it, write cdi_abort info in the debug section
                asm_dest.write(''.join(abort_data))
                if link_tables.write_linkage_tables.done:
                    asm_dest.write(src_line)
                    asm_dest.write(''.join(asm_src.readlines()))
                    break
            if stack_section_decl_matcher.match(src_line):
                stack_section_decl = src_line
            else:
                asm_dest.write(label_interceptor(src_line, asm_src.name))
            src_line = asm_src.readline()
        if not link_tables.write_linkage_tables.done:
            link_tables.write_linkage_tables(asm_dest, cfg, 
                    sled_id_faucet, plt_manager, options)
            link_tables.write_linkage_tables.done = True
        asm_dest.write(stack_section_decl)

        asm_src.close()
        asm_dest.close()

        ## write the rest of the normal asm lines over
        #src_line = asm_src.readline()
        #stack_section_decl = ''
        #stack_section_decl_matcher = re.compile(r'^\s*\.section\s+\.note\.GNU-stack,')
        #while src_line:
        #    if not debug_section_found and debug_section_matcher.match(src_line):
        #        asm_dest.write(''.join(abort_data))
        #    if stack_section_decl_matcher.match(src_line):
        #        stack_section_decl = src_line
        #    else:
        #        asm_dest.write(src_line)
        #    src_line = asm_src.readline()

        #asm_dest.write(stack_section_decl)
            
def cdi_asm_name(asm_name):
    if asm_name.endswith('.fake.o'):
        return asm_name[:-1 * len('.fake.o')] + '.cdi.s'
    elif asm_name.endswith('.s'):
        return asm_name[:-2] + '.cdi.s'
    else:
        assert False

def write_lines(num_lines, asm_src, asm_dest, dwarf_loc, transform_line):
    """Writes from file obj asm_src to file obj asm_dest num_lines lines"""
    i = 0
    while i < num_lines:
        asm_line = asm_src.readline()
        asm_parsing.update_dwarf_loc(asm_line, dwarf_loc)
        asm_dest.write(transform_line(asm_line, asm_src.name))
        i += 1

def convert_to_cdi(site, funct, asm_line, asm_dest, cfg, 
        sled_id_faucet, abort_data, dwarf_loc, options):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""

    if site.group == site.CALL_SITE:
        convert_call_site(site, cfg, funct, asm_line, asm_dest, 
                sled_id_faucet, abort_data, dwarf_loc, options)
    elif site.group == site.RETURN_SITE:
        convert_return_site(site, funct, asm_line, asm_dest, cfg, 
                sled_id_faucet, abort_data, dwarf_loc, options)
    elif site.group == site.INDIR_JMP_SITE:
        convert_indir_jmp_site(site, funct, asm_line, asm_dest)
    elif site.group == site.PLT_SITE:
        convert_plt_site(site, asm_line, funct, asm_dest, options)
    elif site.group == site.GOTPCREL_SITE:
        asm_dest.write(asm_line)
    else:
        eprint('warning: site has invalid type: line ' + site.asm_line_num, 
                'in function named \'' + funct.asm_name + '\'')

def increment_dict(dictionary, key, start = 1):
    dictionary[key] = dictionary.get(key, start - 1) + 1
    return dictionary[key]

reg_map = {
        'rax': 'eax',
        'rcx': 'ecx',
        'rdx': 'edx',
        'rbx': 'ebx',
        'rsp': 'esp',
        'rbp': 'ebp',
        'rsi': 'esi',
        'rdi': 'edi',
}

def reg_64_to_32(register):
    """Returns a 32 bit register given a 64 or 32 bit version"""
    percent = ''
    if register.startswith('%'):
        percent = '%'
        register = register[1:]


    # check if already 32 bit
    if register.startswith('e') or register.endswith('d'):
        return register

    try:
        return percent + reg_map[register]
    except KeyError:
        return percent + register + 'd'


def convert_call_site(site, cfg, funct, asm_line, asm_dest, 
        sled_id_faucet, abort_data, dwarf_loc, options):

    arg_str = asm_parsing.decode_line(asm_line, False)[2]

    # add in return label for return sleds if we're not at an indirect call site
    indirect_call = '%' in arg_str
    if not indirect_call:
        assert len(site.targets) == 1
        target_name = fix_label(site.targets[0].uniq_label)
        times_fixed = increment_dict(funct.label_fixed_count, target_name)
        label = '"_CDIX_FROM_{}_TO_{}_{}"'.format(
                target_name, fix_label(funct.uniq_label), str(times_fixed))

        # only make the label global if the target is from a different unit
        # we do relocations ourselves if we're in a shared library, so don't
        # make it global for shared libraries either
        globl_decl = ''
        # if funct.asm_filename != site.targets[0].asm_filename and not options['--shared-library']:
        if not options['--shared-library']:
            # if funct.asm_filename != site.targets[0].asm_filename or options['--profile-gen']:
            globl_decl = '.globl\t' + label + '\n'

        call = ''

        try:
            libc_exit_fini = cfg.funct('__libc_exit_fini')
        except KeyError:
            libc_exit_fini = None

        if funct is libc_exit_fini:
            call = asm_line
            globl_decl = ''
        elif not options['--shared-library']:
            if options['--profile-gen'] or not cfg.ul_is_cdi(site.targets[0].uniq_label) or funct.asm_name in WHITELIST:
                vvprint("chose no proxy\n")
                call = asm_line
            else:
                vvprint("chose proxy\n")
                proxy_ptr = site.targets[0].proxy_for(label.strip('"'))
                call = '\tpushq ${}\n'.format(hex(proxy_ptr))
                call += asm_line.replace('call', 'jmp', 1)
        else:
            # TODO: use proxy pointers with shared libraries
            target = cfg.funct(site.targets[0].uniq_label)
            if not hasattr(target, 'rel_id_faucet'):
                target.rel_id_faucet = 0

            call = '\t.byte 0xe8\n'
            call += '\t.long 0x00\n'

            call += '"_CDIX_RREL32_{}__CDIX_F_{}":\n'.format(
                 target.rel_id_faucet, target_name)
            target.rel_id_faucet += 1

        asm_dest.write(call + globl_decl + label + ':\n')
        return

    call_sled = ''
    assert len(arg_str.split()) == 1

    if site.targets == []:
        eprint('gen_cdi: warning: indirect call sled is empty on line {} of {} in function {}'
                .format(site.asm_line_num, funct.asm_filename, site.enclosing_funct_uniq_label))

    if not cfg.ul_is_cdi(funct.uniq_label):
        asm_dest.write(asm_line)
        return

    call_operand = arg_str.replace('*', '')
    for target in site.targets:
        target_name = fix_label(target.uniq_label)
        return_target = fix_label(funct.uniq_label)
        times_fixed = increment_dict(funct.label_fixed_count, target_name)

        return_label = '_CDIX_FROM_{}_TO_{}_{}'.format(target_name, return_target,
                str(times_fixed))

        globl_decl = ''
        # if funct.asm_filename != target.asm_filename:
        # if funct.asm_filename != site.targets[0].asm_filename or options['--profile-gen']:
        globl_decl = '.globl\t"{}"\n'.format(return_label)

        call_sled += '1:\n'
        if options['--shared-library']:
            if not hasattr(target, 'rel_id_faucet'):
                target.rel_id_faucet = 0
            call_sled += '\t.byte 0x4c\n'
            call_sled += '\t.byte 0x8d\n'
            call_sled += '\t.byte 0x1d\n'
            call_sled += '\t.long 0x00\n'
            call_sled += '"_CDIX_RREL32_{}__CDIX_F_{}":\n'.format(
                    target.rel_id_faucet, target_name)
            target.rel_id_faucet += 1

            call_sled += '\tcmpq\t%r11, -8(%rsp)\n'
            call_sled += '\tjne\t1f\n'

            call_sled += '\t.byte 0xe8\n'
            call_sled += '\t.long 0x00\n'
            call_sled += '"_CDIX_RREL32_{}__CDIX_F_{}":\n'.format(
                    target.rel_id_faucet, target_name)
            target.rel_id_faucet += 1
        else:
            # create a fp proxy if needed
            if target.fp_proxy is None:
                target.fp_proxy = random.randrange(SIGNED_INT32_MIN, SIGNED_INT32_MAX)
            call_sled += '\tcmpl\t${}, {}\n'.format(hex(target.fp_proxy),
                    reg_64_to_32(call_operand))
            call_sled += '\tjne\t1f\n'
            # eprint("inserting call for ", target_name)
            if options['--profile-gen'] or target is cfg.funct('main') or not cfg.ul_is_cdi(target_name) or funct.asm_name in WHITELIST:
                # eprint("chose 'no proxy'")
                call_sled += '\tcall\t"_CDIX_F_{}"\n'.format(target_name)
            else:
                # eprint("chose 'proxy'")
                call_sled += '\tpushq ${}\n'.format(hex(target.proxy_for(return_label)))
                call_sled += '\tjmp\t"_CDIX_F_{}"\n'.format(target_name)
            # eprint("")

        call_sled += globl_decl
        call_sled += '"{}":\n'.format(return_label)
        call_sled += '\tjmp\t2f\n'

    try:
        init_libc = cfg.funct('__libc_start_init')
    except KeyError:
        init_libc = None

    try:
        libc_start_main = cfg.funct('__libc_start_main')
    except KeyError:
        libc_start_main = None

    try:
        libc_exit_fini = cfg.funct('__libc_exit_fini')
    except KeyError:
        libc_exit_fini = None

    #eprint("init_libc cmp: {} (init libc) vs {} (*)"
    #        .format(init_libc.uniq_label, funct.uniq_label))

    if funct in [init_libc, libc_start_main, libc_exit_fini]:
        call_sled += '1:\n'
        call_sled += asm_line
        call_sled += '\tjmp\t2f\n'


    call_sled += '1:\n'

    # put the call address in temporary register %r10 so that shared library
    # function pointer call sleds can always assume it is in %r10
    if call_operand != '%r10':
        call_sled += '\tmovq\t{}, %r10\n'.format(call_operand)

    code, data = cdi_abort(sled_id_faucet(), funct.asm_filename, 
            dwarf_loc, False, options)

    call_sled += code[0]
    call_sled += '"_CDIX_FPTR_{}_{}":\n'.format(
            fix_label(funct.uniq_label), site.indir_call_id)
    call_sled += code[1]

    if options['--shared-library']:
        # make sure each relocation symbol is unique
        if not hasattr(convert_call_site, 'fptr_id_faucet'):
            convert_call_site.fptr_id_faucet = 0

        # The call will be relocated to point at a call trampoline
        call_sled += '\t.byte 0xe8\n'
        call_sled += '\t.long 0x00\n'
        call_sled += '"_CDIX_RREL32_{}__CDIX_TRAM_C_{}":\n'.format(
                convert_call_site.fptr_id_faucet, site.fptype)
        convert_call_site.fptr_id_faucet += 1

    call_sled += '2:\n'
    asm_dest.write(call_sled)
    abort_data.append(data)

        
cpp_whitelist = ['_Z41__static_initialization_and_destruction_0ii',
        '_GLOBAL__sub_I__Z3barv']

def convert_return_site(site, funct, asm_line, asm_dest, cfg,
        sled_id_faucet, abort_data, dwarf_loc, options):
    
    # don't fix 'main' in this version
    if (funct.asm_name == 'main' or 
            funct.asm_name == '_Z41__static_initialization_and_destruction_0ii' or
            funct.asm_name[:len('_GLOBAL__sub_I__')] == '_GLOBAL__sub_I__'):
        asm_dest.write(asm_line)
        return

    # constructors/destructors run before/after main so they do not need to be
    # fixed up, at least for this version
    if funct.ftype == '(CON/DE)STRUCTOR':
        asm_dest.write(asm_line)
        return
    # PROFILE: Extract sled execution counts
    # If '--profile_use' is supplied sorted_sled is sleds sorted in descending order of execution count
    # Else sorted_sleds is just list of generated sled labels
    if options['--profile-use']:
        profile_file = options.get('--profile-use')
        sled_profile = obj_parse.load_obj(profile_file)

    ret_sled = '\taddq $8, %rsp\n'

    sled_count = {}
    sled_labels = []
    for target_label, multiplicity in site.targets.iteritems(): # PROFILE: generate all sleds of the return site
        i = 1
        while i <= multiplicity:
            sled_label = '_CDIX_FROM_{}_TO_{}_{}'.format(fix_label(funct.uniq_label),
                    fix_label(target_label), str(i))
            i += 1
            if options['--profile-use']:
                if sled_label in sled_profile.keys():
                    sled_count[sled_label] = sled_profile[sled_label]
                else:
                    sled_count[sled_label] = 0
            else:
                sled_labels.append(sled_label)

    # PROFILE: sort sled labels on decreasing order of excution count
    if options['--profile-use']:
        sorted_sleds = sorted(sled_count, key=sled_count.get, reverse=True)
    else:
        sorted_sleds = sled_labels

    for sled_label in sorted_sleds:
        if options['--shared-library']:
            # TODO: use proxy pointers with shared libraries
            ret_sled += '\t.byte 0x4c\n'
            ret_sled += '\t.byte 0x8d\n'
            ret_sled += '\t.byte 0x1d\n'
            ret_sled += '\t.long 0x00\n'
            ret_sled += '"_CDIX_RREL32_{}_{}":\n'.format(
                    '0', sled_label)
            ret_sled += '\tcmpq\t%r11, -8(%rsp)\n'

            ret_sled += '\t.byte 0x0f\n'
            ret_sled += '\t.byte 0x84\n'
            ret_sled += '\t.long 0x00\n'
            ret_sled += '"_CDIX_RREL32_{}_{}":\n'.format(
                    '1', sled_label)
        else:
            target = sled_label
            target = target[target.find('_TO_') + len('_TO_'):]
            target = remove_multiplicity(target)
            target = target[target.rfind('.') + 1:]
            if options['--profile-gen'] or target in WHITELIST:
                ret_sled += '\tcmpq\t$"{}", -8(%rsp)\n'.format(sled_label)
            else:
                proxy_ptr = funct.proxy_for(sled_label.strip("'"))
                ret_sled += '\tcmpq\t${}, -8(%rsp)\n'.format(hex(proxy_ptr))
            ret_sled += '\tje\t"' + sled_label + '"\n'
    # subtract another 8 bytes off the stack pointer since we'll be 
    # using two return address on the way back: one to get from the SLT
    # to the RLT and another to get from the RLT to the executable code
    #
    # Even if this we're looking at the executable, we must include the extra
    # add in case this sled is linked to a fp ret sled
    ret_sled += '\taddq $8, %rsp\n' # TODO: fix this for proxies

    code, data = cdi_abort(sled_id_faucet(), funct.asm_filename,
            dwarf_loc, True, options)
    ret_sled += code[0]
    ret_sled += '"_CDIX_RET_{}_{}":\n'.format(
            fix_label(funct.uniq_label), site.ret_id)
    ret_sled += code[1]

    if options['--shared-library']:
        # make sure each relocation symbol is unique
        if not hasattr(funct, 'rel_id_faucet'):
            funct.rel_id_faucet = 0

        # The jmp will be relocated to point at a return trampoline
        ret_sled += '\t.byte 0xe9\n'
        ret_sled += '\t.long 0x00\n'
        ret_sled += '"_CDIX_RREL32_{}__CDIX_TRAM_R_{}":\n'.format(
                funct.rel_id_faucet, fix_label(funct.uniq_label))
        funct.rel_id_faucet += 1

    abort_data.append(data)
    asm_dest.write(ret_sled)

class FunctLabelInterceptor:
    def __init__(self, cfg):
        # needed to know which labels are function labels or aliases
        self.cfg = cfg

        # maps function object to a globally agreed upon proxy
        self.fp_proxies = dict()

        # intercepts function label use like 'mov $foo, %rax\n'
        self.code_matcher = re.compile(r'\$[a-zA-Z_]+[a-zA-Z0-9_]*')

        # intercepts function label use like '.quad foo\n'
        self.data_matcher = re.compile(r'\s*\.quad\s+[a-zA-Z_]\w*\s*$')
        self.end_label_matcher = re.compile(r'[^a-zA-Z0-9_$]+')

    def __call__(self, asm_line, asm_filename):
        """Returns a line with all function labels rewritten with a proxy"""
        match = self.code_matcher.search(asm_line)
        is_code_match = True

        label_idx = None
        if match is None:
            is_code_match = False
            match = self.data_matcher.search(asm_line)
            if match is None:
                return asm_line
            vprint('found funct label used in data')
            # find the label position
            vprint('whats left: "{}"'.format(asm_line[asm_line.find('.quad') + len('.quad'):]))
            for idx in range(asm_line.find('.quad') + len('.quad'), len(asm_line)):
                if asm_line[idx] not in string.whitespace:
                    label_idx = idx
                    break
            else:
                eprint("gen_cdi: error: no label found in '{}'".format(asm_line))
                sys.exit(1)
            vprint(asm_line[label_idx:])
        else:
            label_idx = match.start()

        prefix, remaining = asm_line[:label_idx], asm_line[label_idx:]
        end_label_match = self.end_label_matcher.search(remaining)
        if end_label_match is None:
            eprint("error: expected end to label in '{}'".format(asm_line))
            sys.exit(1)

        match_idx = end_label_match.start()
        label, suffix = remaining[:match_idx], remaining[match_idx:]
        if label.startswith('$'):
            label = label[1:]


        # mov   $foo,   %rax
        # AAAAAA BBBCCCCCCCC
        #
        # (or)
        # .quad foo
        # AAAAAABBBCCCCCCC...
        #
        # prefix = A
        # label  = B
        # suffix = C

        if label in FP_WHITELIST:
            return asm_line

        try:
            funct = self.cfg.funct(label)
        except KeyError:
            try:
                uniq_label = '{}.{}'.format(asm_filename, label)
                vprint("checking for function with ul: '{}'".format(uniq_label))
                funct = self.cfg.funct(uniq_label)
            except KeyError:
                eprint("warning: XXX: NO FUNCTION HIT FOR LABEL: '{}'".format(label))
                return asm_line

        eprint("FUNCTION HIT FOR LABEL: '{}'".format(label))
        if funct.fp_proxy is None:
            funct.fp_proxy = random.randrange(SIGNED_INT32_MIN, SIGNED_INT32_MAX)
        eprint('filename: {}'.format(asm_filename))
        eprint('old line: {}'.format(asm_line[:-1]))

        dollar = ''
        if is_code_match:
            dollar = '$'

        eprint('new line: {}{}{}{}'.format(prefix, dollar, hex(funct.fp_proxy), suffix))
        return '{}{}{}{}'.format(prefix, dollar, hex(funct.fp_proxy), suffix)

SIGNED_INT32_MIN = -1 * (1 << 31)
SIGNED_INT32_MAX = (1 << 31) - 1


def convert_indir_jmp_site(site, funct, asm_line, asm_dest):
    pass

def convert_plt_site(site, asm_line, funct, asm_dest, options):
    return_label = site.label

    globl_decl = ''
    if not options['--shared-library']:
        globl_decl = '.globl\t{}\n'.format(return_label)
    asm_dest.write(asm_line + globl_decl + return_label + ':\n') 

def fix_label(label):
    return label.replace('@PLT', '').replace('/', '__').replace('.fake.o', '.cdi.s')

def remove_multiplicity(label):
    return label[:label.rfind('_')]
