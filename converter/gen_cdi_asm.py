import __init__

import funct_cfg
import operator
import asm_parsing
import subprocess
import sys
import re
import os

from common.eprint import eprint

# CDI Label Conventions
###########################
# Labels are used to coordinate the jumps needed for returns and indirect calls. Labels 
# are also used to designate SLT entries, RLT entries, and even relocations. What
# follows is a general format for CDI labels. '||' is the concatenation symbol
#
#   _CDI || [deletable] || _ || [type] || _ || [type dependent data or tdd for short]
#
# The second field [deletable] is filled with an 'X' if the symbol is unneeded
# at load time. [type] specifies what purpose the label is used for.
#
#  Type    | Label purpose
#  --------+------------
#  RET     | Used to coordinate return sleds and indirect call sleds. A sled label's
#          | multiplicity is used to differentiate between other call/returns from the 
#          | same two functions. Calls with higher VMAs have higher multiplicities
#          | [tdd] := [called funct's uniq_label] || _TO_ || [return funct's uniq_label] || _ || [multiplicity]
#          |
#  PLT     | Like RET but it's used to coordinate RLT sleds and how they return to
#          | after calls into the PLT.
#          | [tdd] := [PLT symbol] || _TO_ || [return funct's uniq_label] || _ || [multiplicity]
#          |
#  F       | A global version of a function symbol. Used to call/jump from other asm units
#          | [tdd] := [function's uniq_label]
#          |
#  RLT     | Marks an RLT entry. These labels are needed for the CDI loader
#          | [tdd] := [the associated shared library symbol]
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
#  --------+------------
#
# Special labels:
#   _CDI_SLT_tramptab: specifies the beginning of the SLT trampoline table
#   _CDI_callback_sled: specifies the beginning of the shared library callback sled
#   _CDI_abort: points to a function that prints out sled debug info and exits
#   _CDIX_dummy_sym: gives jmps that will be relocated by cdi-ld a dummy target

def gen_cdi_asm(cfg, asm_file_descrs, plt_sites, options):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    sled_id_faucet = funct_cfg.SledIdFaucet()

    write_rlt.done = False
    write_slt_tramptab.done = False
    write_callback_sled.done = False
    
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
            write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)
            asm_line_num = funct.asm_line_num

            # unique labels are always global so that even static functions
            # can be reached from anywhere with sleds (Function pointers can
            # point to ANY function with the same signature, even static 
            # functions in a different translation unit)
            asm_dest.write('.globl\t"_CDIX_F_{}"\n'.format(fix_label(funct.uniq_label)))
            asm_dest.write('"_CDIX_F_{}":\n'.format(fix_label(funct.uniq_label)))

            funct.label_fixed_count = dict()
            for site in funct.sites:
                num_lines_to_write = site.asm_line_num - asm_line_num
                write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)

                line_to_fix = asm_src.readline()
                asm_line_num = site.asm_line_num + 1
                
                convert_to_cdi(site, funct, line_to_fix, asm_dest, cfg,
                        sled_id_faucet, abort_data, dwarf_loc, options)
                        


        debug_section_matcher = re.compile(r'^\t\.section\t\.debug_info.+')
        debug_section_found = False


        if not write_callback_sled.done and options['--sl-fptr-addrs']:
            write_callback_sled(asm_dest, options)
            write_callback_sled.done = True

        # write the rest of the normal asm lines over
        src_line = asm_src.readline()
        stack_section_decl = ''
        stack_section_decl_matcher = re.compile(r'^\s*\.section\s+\.note\.GNU-stack,')
        while src_line:
            if not debug_section_found and debug_section_matcher.match(src_line):
                asm_dest.write(''.join(abort_data))
            if stack_section_decl_matcher.match(src_line):
                stack_section_decl = src_line
            else:
                asm_dest.write(src_line)
            src_line = asm_src.readline()

        if not write_rlt.done:
            asm_dest.write('\t.text\n')
            write_rlt(cfg, plt_sites, asm_dest, sled_id_faucet, options)
            write_rlt.done = True

        # jmps that will be relocated by cdi-ld need a dummy target
        asm_dest.write('_CDIX_dummy_sym:\n\t.long 0xdeadbeef\n')

        if not write_slt_tramptab.done and options['--shared-library']:
            write_slt_tramptab(asm_dest, cfg, options)
            write_slt_tramptab.done = True
        
        asm_dest.write(stack_section_decl)
        asm_src.close()
        asm_dest.close()
            
def cdi_asm_name(asm_name):
    if asm_name.endswith('.fake.o'):
        return asm_name[:-1 * len('.fake.o')] + '.cdi.s'
    elif asm_name.endswith('.s'):
        return asm_name[:-2] + '.cdi.s'
    else:
        assert False

def write_lines(num_lines, asm_src, asm_dest, dwarf_loc):
    """Writes from file obj asm_src to file obj asm_dest num_lines lines"""
    i = 0
    while i < num_lines:
        asm_line = asm_src.readline()
        asm_parsing.update_dwarf_loc(asm_line, dwarf_loc)
        asm_dest.write(asm_line)
        i += 1

def convert_to_cdi(site, funct, asm_line, asm_dest, cfg, 
        sled_id_faucet, abort_data, dwarf_loc, options):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""

    if site.group == site.CALL_SITE:
        convert_call_site(site, funct, asm_line, asm_dest, 
                sled_id_faucet, abort_data, dwarf_loc, options)
    elif site.group == site.RETURN_SITE:
        convert_return_site(site, funct, asm_line, asm_dest, cfg, 
                sled_id_faucet, abort_data, dwarf_loc, options)
    elif site.group == site.INDIR_JMP_SITE:
        convert_indir_jmp_site(site, funct, asm_line, asm_dest)
    elif site.group == site.PLT_SITE:
        convert_plt_site(site, asm_line, funct, asm_dest)
    else:
        eprint('warning: site has invalid type: line ' + site.asm_line_num, 
                'in function named \'' + funct.asm_name + '\'')

def increment_dict(dictionary, key, start = 1):
    dictionary[key] = dictionary.get(key, start - 1) + 1
    return dictionary[key]

def convert_call_site(site, funct, asm_line, asm_dest, 
        sled_id_faucet, abort_data, dwarf_loc, options):

    arg_str = asm_parsing.decode_line(asm_line, False)[2]

    # add in return label for return sleds if we're not at an indirect call site
    indirect_call = '%' in arg_str
    if not indirect_call:
        assert len(site.targets) == 1
        target_name = fix_label(site.targets[0].uniq_label)
        times_fixed = increment_dict(funct.label_fixed_count, target_name)
        label = '"_CDIX_RET_{}_TO_{}_{}"'.format(
                target_name, fix_label(funct.uniq_label), str(times_fixed))

        globl_decl = ''
        if funct.asm_filename != site.targets[0].asm_filename:
            globl_decl = '.globl\t' + label + '\n'

        asm_dest.write(asm_line + globl_decl + label + ':\n')
        return
    elif options['--shared-library']:
        eprint('gen_cdi: error: function pointers are currently forbidden from CDI shared libraries')
        sys.exit(1)

    call_sled = ''
    assert len(arg_str.split()) == 1

    if site.targets == []:
        eprint('gen_cdi: warning: indirect call sled is empty on line {} of {} in function {}'
                .format(site.asm_line_num, funct.asm_filename, site.enclosing_funct_uniq_label))

    call_operand = arg_str.replace('*', '')
    for target in site.targets:
        target_name = fix_label(target.uniq_label)
        return_target = fix_label(funct.uniq_label)
        times_fixed = increment_dict(funct.label_fixed_count, target_name)

        return_label = '_CDIX_RET_{}_TO_{}_{}'.format(target_name, return_target,
                str(times_fixed))

        globl_decl = ''
        if funct.asm_filename != target.asm_filename:
            globl_decl = '.globl\t"{}"\n'.format(return_label)

        call_sled += '1:\n'
        if options['--shared-library']:
            call_sled += '\tcmpq\t$"{}(%rip)", {}\n'.format(target_name, call_operand)
        else:
            call_sled += '\tcmpq\t$"_CDIX_F_{}", {}\n'.format(target_name, call_operand)
            call_sled += '\tjne\t1f\n'
            call_sled += '\tcall\t"_CDIX_F_{}"\n'.format(target_name)
        call_sled += globl_decl
        call_sled += '"{}":\n'.format(return_label)
        call_sled += '\tjmp\t2f\n'

    call_sled += '1:\n'
    # put the unsafe target address in %rax so that cdi_abort prints it out
    if call_operand != '%rax':
        call_sled += '\tmovq\t{}, %rax\n'.format(call_operand)
    code, data =cdi_abort(sled_id_faucet(), funct.asm_filename, 
            dwarf_loc, False, options)
    call_sled += code
    abort_data.append(data)
    call_sled += '2:\n'
    asm_dest.write(call_sled)

        
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
    if funct.ftype.mangled_str == '(CON/DE)STRUCTOR':
        asm_dest.write(asm_line)
        return

    ret_sled = '\taddq $8, %rsp\n'
    for target_label, multiplicity in site.targets.iteritems():
        eprint(target_label, multiplicity)
        i = 1
        while i <= multiplicity:
            sled_label = '_CDIX_RET_{}_TO_{}_{}'.format(fix_label(funct.uniq_label),
                    fix_label(target_label), str(i))
            if options['--shared-library']:
                ret_sled += '\tnop\n' * 7
                ret_sled += '"_CDIX_RREL32P_{}_{}_{}":\n'.format(
                        '4c8d1d', '0', sled_label)
                ret_sled += '\tcmpq\t%r11, -8(%rsp)\n'

                ret_sled += '\tnop\n' * 6
                ret_sled += '"_CDIX_RREL32P_{}_{}_{}":\n'.format(
                        '0f84', '1', sled_label)
            else:
                ret_sled += '\tcmpq\t$"' + sled_label + '", -8(%rsp)\n'
                ret_sled += '\tje\t"' + sled_label + '"\n'
            i += 1


    code, data = cdi_abort(sled_id_faucet(), funct.asm_filename,
            dwarf_loc, True, options)
    if options['--shared-library']:
        # only fill %r11 with data. Do not add a jump to _CDI_abort
        ret_sled += code[:code.find('\n', code.find('_CDIX_SLED_')) + 1]

        # make sure each relocation symbol is unique
        if not hasattr(funct, 'rel_id_faucet'):
            funct.rel_id_faucet = 0

        # The jmp will be relocated to jmp to an SLT trampoline entry
        ret_sled += '\tnop\n' * 5
        ret_sled += '_CDIX_RREL32P_{}_{}__CDI_SLT_tramptab_{}:\n'.format(
                'e9', funct.rel_id_faucet, fix_label(funct.uniq_label))
        funct.rel_id_faucet += 1

    abort_data.append(data)
    asm_dest.write(ret_sled)

def convert_indir_jmp_site(site, funct, asm_line, asm_dest):
    pass

def cdi_abort(sled_id, asm_filename, dwarf_loc, try_callback_sled, options):
    """Return (code, data) that allows for aborting with sled-specific info.
    
    Code should be placed at the end of a return/call sled. data should be 
    placed away from code so that the verifier works correctly.
    """


    loc_str = asm_filename.replace('.fake.o', '.cdi.s')
    if dwarf_loc.valid():
        loc_str = '{}:{}/{}'.format(str(dwarf_loc), os.path.basename(os.getcwd()), loc_str)

    cdi_abort_code = cdi_abort_data = ''
    if options['--shared-library']:
        # prepare %rsi with sled info (this is lea)
        cdi_abort_code += '\tnop\n' * 7
        cdi_abort_code += '"_CDIX_RREL32P_{}_{}_{}":\n'.format(
                '4c8d1d', str(sled_id), '_CDIX_SLED_' + str(sled_id))

        # jump to _CDI_abort
        cdi_abort_code += '\tnop\n' * 5
        cdi_abort_code += '"_CDIX_RREL32P_{}_{}_{}":\n'.format(
                'e9', str(sled_id), '_CDI_abort')
    elif options['--sl-fptr-addrs'] and try_callback_sled:
        cdi_abort_code += '\tmovq\t $_CDIX_SLED_' + str(sled_id) + ', %r11\n'
        cdi_abort_code += '\tjmp\t_CDI_callback_sled\n'
    else:
        cdi_abort_code += '\tmovq\t $_CDIX_SLED_' + str(sled_id) + ', %rsi\n'
        cdi_abort_code += '\tcall\t_CDI_abort\n'

    cdi_abort_msg = loc_str + ' id=' + str(sled_id)
    cdi_abort_data += '_CDIX_SLED_' + str(sled_id) + ':\n'
    cdi_abort_data += '\t.quad\t' + str(len(cdi_abort_msg)) + '\n'
    cdi_abort_data += '\t.string\t"' + cdi_abort_msg + '"\n'

    return (cdi_abort_code, cdi_abort_data)

def convert_plt_site(site, asm_line, funct, asm_dest):
    if not hasattr(funct, 'plt_call_multiplicity'):
        funct.plt_call_multiplicity = dict()

    try:
        funct.plt_call_multiplicity[(site.targets[0], funct.uniq_label)] += 1
    except KeyError:
        funct.plt_call_multiplicity[(site.targets[0], funct.uniq_label)] = 1

    # create label for RLT to return to
    rlt_return_label = ('"_CDIX_PLT_{}_TO_{}_{}"'
            .format(fix_label(site.targets[0]), fix_label(funct.uniq_label), 
                str(funct.plt_call_multiplicity[(site.targets[0], funct.uniq_label)])))

    globl_decl = '.globl\t' + rlt_return_label + '\n'
    asm_dest.write(asm_line + globl_decl + rlt_return_label + ':\n') 

def write_rlt(cfg, plt_sites, asm_dest, sled_id_faucet, options):
    """Write the RLT to asm_dest"""

    # maps (shared library uniq label, rlt return target) -> multiplicity
    multiplicity = dict()

    # maps shared library uniq label -> set of potential functions to which to return
    rlt_return_targets = dict()

    # populate the multiplicity and rlt_return_targets dicts
    for plt_site in plt_sites:
        call_return_pair = (plt_site.targets[0], plt_site.enclosing_funct_uniq_label)

        if plt_site.targets[0] not in rlt_return_targets:
            rlt_return_targets[plt_site.targets[0]] = set()
        rlt_return_targets[call_return_pair[0]].add(call_return_pair[1])

        try:
            multiplicity[call_return_pair] += 1
        except KeyError:
            multiplicity[call_return_pair] = 1


    # An RLT trampoline table is unnecessary. Leave it here just in case we 
    # need it later
    #
    # create the RLT trampoline table
    #rlt_jump_table = '\t.type\t_CDI_RLT_JUMP_TABLE, @function\n'
    #rlt_jump_table += '_CDI_RLT_JUMP_TABLE:\n'
    #for sl_funct_uniq_label in rlt_return_targets.keys():
    #    entry_label = '"_CDI_RLT_{}"'.format(fix_label(sl_funct_uniq_label))
    #    rlt_jump_table += '\tjmp {}\n'.format(entry_label)
    #rlt_jump_table += '\t.size\t_CDI_RLT_JUMP_TABLE, .-_CDI_RLT_JUMP_TABLE\n'
    #
    #asm_dest.write(rlt_jump_table)

    # create an RLT entry for each shared library function

    asm_dest.write('\t.section .cdi_rlt, "ax", @progbits\n')
    
    rlt_relocation_id_faucet = 0
    cdi_abort_data = ''
    for sl_funct_uniq_label, rlt_target_set in rlt_return_targets.iteritems():
        rlt_entry = ''

        entry_label = '"_CDI_RLT_{}"'.format(fix_label(sl_funct_uniq_label))

        # reserve space for cdi-ld to store the associated PLT return address
        asm_dest.write('\t.quad 0xdeadbeefefbeadde\n')
        asm_dest.write('\t.type {}, @function\n'.format(entry_label))
        asm_dest.write(entry_label + ':\n')

        # Add sled entries for each RLT target
        for rlt_target in rlt_target_set:
            i = 1
            while i <= multiplicity[(sl_funct_uniq_label, rlt_target)]:
                sled_label = '"_CDIX_PLT_{}_TO_{}_{}"'.format(
                        fix_label(sl_funct_uniq_label), fix_label(rlt_target) , str(i))
                if options['--shared-library']:
                    # we must do this because putting the 'lea' here will require
                    # a relocation if the symbol is outside this assembly file, 
                    # which the linker will complain about. Instead, we do the 
                    # relocation ourselves in cdi-ld. Point the lea at a dummy
                    # target for now
                    rlt_entry += '\tnop\n' * 7
                    rlt_entry += '"_CDIX_RREL32P_{}_{}_{}:\n'.format(
                            '4c8d1d', str(rlt_relocation_id_faucet), sled_label[1:])
                    rlt_entry += '\tcmpq\t%r11, -8(%rsp)\n'
                    rlt_relocation_id_faucet += 1

                    # we must do this relocation ourselves too
                    rlt_entry += '\tnop\n' * 6
                    rlt_entry += '"_CDIX_RREL32P_{}_{}_{}:\n'.format(
                            '0f84', str(rlt_relocation_id_faucet), sled_label[1:])
                    rlt_relocation_id_faucet += 1
                else:
                    rlt_entry += '\tcmpq\t$' + sled_label + ', -8(%rsp)\n'
                    rlt_entry += '\tje\t' + sled_label + '\n'
                i += 1

        code, data = cdi_abort(sled_id_faucet(), '',
            asm_parsing.DwarfSourceLoc(), False, options)
        cdi_abort_data += data
        rlt_entry += code
        rlt_entry += '\t.size {}, .-{}\n'.format(entry_label, entry_label)
        asm_dest.write(rlt_entry)
    asm_dest.write(cdi_abort_data)

def write_slt_tramptab(asm_dest, cfg, options):
    page_size = subprocess.check_output(['getconf', 'PAGESIZE'])
    asm_dest.write('\t.section .cdi_slt_tramptab, "ax", @progbits\n')
    asm_dest.write('\t.align {}\n'.format(page_size))
    asm_dest.write('\t.globl _CDI_SLT_tramptab\n')
    asm_dest.write('_CDI_SLT_tramptab:\n')
    for funct in cfg:
        slt_entry_label = '"_CDI_SLT_tramptab_{}"'.format(fix_label(funct.uniq_label))
        asm_dest.write('\t.globl {}\n'.format(slt_entry_label))
        asm_dest.write(slt_entry_label + ':\n')

        # Save space for a jump. This will be fixed up by the loader
        asm_dest.write('\t.byte 0xe9\n')
        asm_dest.write('\tnop\n' * 4)
        asm_dest.write('\tnop\n' * 3) # this will hold a symtab index

    asm_dest.write('\t.size _CDI_SLT_tramptab, .-_CDI_SLT_tramptab\n')
    asm_dest.write('\t.align {}\n'.format(page_size))

def write_callback_sled(asm_dest, options):
    callback_sled = '.globl _CDI_callback_sled\n'
    callback_sled += '_CDI_callback_sled:\n'

    # the callback table is in the following format:
    #
    # "/path/to/library.so" load-addr: 0xADDRESS
    # fptr address 1
    # fptr address 2
    # ...
    #
    # "/path/to/library2.so" load-addr: 0xADDRESS
    # ...
    #
    #
    # The end of a library is indicated by two consecutive newlines

    # populated with pairs of (library metadata, list of fptrs)
    fptr_table = []
    with open(options['--sl-fptr-addrs'], 'r') as callback_table:
        lines = iter(callback_table)
        for lib_metadata in lines:
            lib_fptrs = []
            line = lines.next()
            while line != '\n':
                lib_fptrs.append(line.rstrip())
                line = lines.next()
            fptr_table.append((lib_metadata.rstrip(), lib_fptrs))

    for lib_metadata, fptrs in fptr_table:
        upper_to_lower_addrs = dict()
        for addr in fptrs:
            lower_addr = '0x' + addr[-8:]
            upper_addr = addr[:-8]
            try:
                upper_to_lower_addrs[upper_addr].append(lower_addr)
            except KeyError:
                upper_to_lower_addrs[upper_addr] = [lower_addr]

        callback_sled += '/* {} */\n'.format(lib_metadata)
        for upper_addr, lower_addrs in upper_to_lower_addrs.iteritems():
            callback_sled += '\tcmpl\t$'+upper_addr+', -4(%rsp)\n'
            callback_sled += '\tjne\t1f\n'
            for addr in lower_addrs:
                callback_sled += '\tcmpl\t$'+addr+', -8(%rsp)\n'
                callback_sled += '\tjne\t2f\n'
                callback_sled += '\tmov\t$'+upper_addr+addr[2:]+', %r11\n'
                callback_sled += '\tjmp\t*%r11\n'
                callback_sled += '2:\n'
            callback_sled += '1:\n'
    callback_sled += '\tmovq\t-8(%rsp), %rax\n'
    callback_sled += '\tmovq\t%r11, %rsi\n'
    callback_sled += '\tcall _CDI_abort\n'
    asm_dest.write(callback_sled)

def fix_label(label):
    return label.replace('@PLT', '').replace('/', '__').replace('.fake.o', '.cdi.s')

