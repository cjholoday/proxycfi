import __init__


import copy
import operator
import asm_parsing
import subprocess
import sys
import re
import os
import struct
import itertools


import funct_cfg

from common.eprint import eprint
from cdi_abort import cdi_abort

def write_linkage_tables(asm_dest, cfg, sled_id_faucet, plt_manager, options):
    fptr_sites = []
    for funct in cfg:
        for site in funct.sites:
            if site.fptype != None:
                fptr_sites.append(site)

    asm_dest.write('\t.text\n')
    write_slow_plt(asm_dest, cfg)
    if options['--sl-fptr-addrs']:
        write_callback_sled(asm_dest, options)

    write_rlt(cfg, plt_manager, asm_dest, sled_id_faucet, options)

    if options['--shared-library']:
        page_size = subprocess.check_output(['getconf', 'PAGESIZE'])

        # the trampolines must be on their own page, so that the rest of 
        # the shared library code/data is shared
        asm_dest.write('\t.align {}\n'.format(page_size))
        asm_dest.write('\t.section .cdi_tramtab, "ax", @progbits\n')
        asm_dest.write('\t.globl _CDI_tramtab\n')
        asm_dest.write('_CDI_tramtab:\n')

        num_fptr_sleds = len(fptr_sites)

        # Consume one trampoline to specify the number of return/call sleds
        asm_dest.write('\t.quad {}\n'.format(cfg.size())) # num return sleds
        asm_dest.write('\t.quad {}\n'.format(num_fptr_sleds)) # num call sleds

        cdi_strtab = write_ret_trams(asm_dest, cfg, options)
        write_call_trams(asm_dest, fptr_sites, options)
        asm_dest.write('\t.align {}\n'.format(page_size))

        asm_dest.write('\t.section .cdi_strtab, "a", @progbits\n')
        write_strtab(asm_dest, cdi_strtab)
    write_typetabs(asm_dest, cfg, fptr_sites)

def write_slow_plt(asm_dest, cfg):
    """Writes the .slow_plt section, which reserves 16 bytes for every fast plt"""
    
    # contains a set of all unique GOT names for GOTPCREL sites
    gotpcrel_set = set()
    for funct in cfg:
        for site in funct.sites:
            if (site.group == funct_cfg.Site.GOTPCREL_SITE 
                    and site.got_name not in gotpcrel_set):
                gotpcrel_set.add(site.got_name)
    asm_dest.write('\t.align 16\n')
    asm_dest.write('\t.section .slow_plt, "ax", @progbits\n')
    asm_dest.write('\t_CDI_slow_plt:\n')
    asm_dest.write('\t.quad 0x0\n' * (2 * len(gotpcrel_set)))

    # write two extra slow plts because there are always two fast plts by default
    asm_dest.write('\t.quad 0x0\n' * 2)

    # write one more slow plt so that the .slow_plt section is never empty
    asm_dest.write('\t.quad 0x0\n' * 2)
    asm_dest.write('\t.section .cdi_seg_end, "a", @progbits\n')

    # include calls to each GOTPCREL symbol so that the fast plt entries 
    # are always created. if there is no direct call to the symbols
    asm_dest.write('\t.section .cdi_seg_end, "a", @progbits\n')
    for got_name in gotpcrel_set:
        asm_dest.write('\tcallq {}@PLT\n'.format(got_name))


def write_rlt(cfg, plt_manager, asm_dest, sled_id_faucet, options):
    """Write the RLT to asm_dest"""

    # maps (shared library uniq label, rlt return target) -> multiplicity
    multiplicity = dict()

    # maps shared library uniq label -> set of potential functions to which to return
    rlt_return_targets = dict()

    # populate the multiplicity and rlt_return_targets dicts
    for plt_site in itertools.chain(*list(plt_manager.sites.values())):
        call_return_pair = (plt_site.targets[0], plt_site.enclosing_funct_uniq_label)

        if plt_site.targets[0] not in rlt_return_targets:
            rlt_return_targets[plt_site.targets[0]] = set()
        rlt_return_targets[call_return_pair[0]].add(call_return_pair[1])

        try:
            multiplicity[call_return_pair] += 1
        except KeyError:
            multiplicity[call_return_pair] = 1

    # create an RLT entry for each shared library function

    asm_dest.write('\t.section .cdi_rlt, "ax", @progbits\n')
    
    rlt_relocation_id_faucet = 0
    cdi_abort_data = ''
    for sl_funct_uniq_label, rlt_target_set in rlt_return_targets.iteritems():
        rlt_entry = ''

        entry_label = '"_CDI_RLT_{}"'.format(fix_label(sl_funct_uniq_label))

        # reserve space for cdi-ld to store the associated PLT return address
        asm_dest.write('\t.align 8\n') # make sure PLT ret addr is aligned
        asm_dest.write('\t.quad 0xdeadbeefefbeadde\n')
        asm_dest.write('\t.type {}, @function\n'.format(entry_label))
        asm_dest.write('\t.globl {}\n'.format(entry_label))
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
                    # relocation ourselves in cdi-ld. 
                    
                    rlt_entry += '\t.byte 0x4c\n'
                    rlt_entry += '\t.byte 0x8d\n'
                    rlt_entry += '\t.byte 0x1d\n'
                    rlt_entry += '\t.long 0x00\n'
                    rlt_entry += '"_CDIX_RREL32_{}_{}:\n'.format(
                            str(rlt_relocation_id_faucet), sled_label[1:])
                    rlt_entry += '\tcmpq\t%r11, -8(%rsp)\n'
                    rlt_relocation_id_faucet += 1

                    # we must do this relocation ourselves too
                    rlt_entry += '\t.byte 0x0f\n'
                    rlt_entry += '\t.byte 0x84\n'
                    rlt_entry += '\t.long 0x00\n'
                    rlt_entry += '"_CDIX_RREL32_{}_{}:\n'.format(
                            str(rlt_relocation_id_faucet), sled_label[1:])
                    rlt_relocation_id_faucet += 1
                else:
                    rlt_entry += '\tcmpq\t$' + sled_label + ', -8(%rsp)\n'
                    rlt_entry += '\tje\t' + sled_label + '\n'
                i += 1

        code, data = cdi_abort(sled_id_faucet(), '',
            asm_parsing.DwarfSourceLoc(), False, options)
        cdi_abort_data += data
        rlt_entry += ''.join(code)
        rlt_entry += '\t.size {}, .-{}\n'.format(entry_label, entry_label)
        asm_dest.write(rlt_entry)
    asm_dest.write(cdi_abort_data)

def write_ret_trams(asm_dest, cfg, options):
    """Write return trampolines and return the cdi_strtab as a string"""
    # make sure there is enough space to write _CDI_RLT_ 
    # before every string in .cdi_strtab. 
    cdi_strtab = '\x00_CDI_RLT_\x00'
    for funct in cfg:
        # reserve 0 for return trampolines
        label = '"_CDIX_TRAM_R_{}"'.format(fix_label(funct.uniq_label))
        asm_dest.write('\t.globl {}\n'.format(label))
        asm_dest.write(label + ':\n')

        # Save 13 bytes for a jump (movabs <addr>, %r10; jmp *%r10)
        # this may be filled with a 5 byte jump to the SLT, but we must save
        # the full 13 bytes in case we need t jump to a fptr return sled
        asm_dest.write('\t.quad 0x0\n')
        asm_dest.write('\t.long 0x0\n')
        asm_dest.write('\t.byte 0x0\n')

        # make sure the strtab index can fit in 3 bytes
        if len(cdi_strtab) >= (1 << (8 * 3)):
            eprint('gen_cdi: error: .cdi_strtab index cannot fit in 3 bytes')
            sys.exit(1)

        # write the .cdi_strtab index into the 3 bytes after the trampoline jmp
        # but only for global functions since only those can be directly called
        # from outside the shared library. We only need the symbol for a trampoline
        # if there will be an SLT entry for the function
        if funct.is_global:
            for byte in struct.pack('<I', len(cdi_strtab))[:-1]:
                asm_dest.write('\t.byte {}\n'.format(hex(struct.unpack('B', byte)[0])))
            cdi_strtab += funct.asm_name + '\x00'
        else:
            asm_dest.write('\t.byte 0x0\n' * 3)


    return cdi_strtab

def write_call_trams(asm_dest, fptr_sites, options):
    types_handled = set()
    for site in fptr_sites:
        # only create one trampoline for each function pointer type
        if site.fptype in types_handled:
            continue
        types_handled.add(site.fptype)

        label = '"_CDIX_TRAM_C_{}"'.format(site.fptype)
        asm_dest.write('\t.globl {}\n'.format(label))
        asm_dest.write(label + ':\n')

        # save space for a movabs <jmp addr>, %r10; jmp *%r10
        # we keep the code aligned to 16 bytes for speed and simplicity
        asm_dest.write('\t.quad 0x0\n')
        asm_dest.write('\t.quad 0x0\n')


def write_strtab(asm_dest, strtab):
    # now translate the strtab into assembler
    strtab = strtab.split('\x00')[1:-1]
    asm_dest.write('\t.string ""')

    for string in strtab:
        asm_dest.write(', "{}"'.format(string))
    asm_dest.write('\n')

def write_callback_sled(asm_dest, options):
    asm_dest.write('\t.section .unsafe_callbacks, "ax", @progbits\n')

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
    callback_sled += '\tjmp _CDI_abort\n'
    asm_dest.write(callback_sled)

class FloctabEntry:
    def __init__(self):
        self.f_reloffs = ''
        self.fret_reloffs = ''

        self.num_f_reloffs = 0
        self.num_fret_reloffs = 0

class FploctabEntry:
    def __init__(self):
        self.site_reloffs = ''
        self.num_site_reloffs = 0

def write_typetabs(asm_dest, cfg, fptr_sites):
    functs = cfg.functs()

    curr_loctab_entry = FloctabEntry()
    def on_type_used(funct, loctab_entry = curr_loctab_entry):
        # store the relative offset to the function and its return sites
        # use RREL32 relocations to set the offsets 
        loctab_entry.f_reloffs += ('\t.long 0x0\n"_CDIX_RREL32_floctab__CDIX_F_{}":\n'
                .format(fix_label(funct.uniq_label)))
        loctab_entry.num_f_reloffs += 1

        for ret_id in xrange(funct.num_rets):
            loctab_entry.fret_reloffs += ('\t.long 0x0\n"_CDIX_RREL32_0__CDIX_RET_{}_{}":\n'
                    .format(fix_label(funct.uniq_label), ret_id))
        loctab_entry.num_fret_reloffs += funct.num_rets

    floctab = []
    def on_type_exhausted(floctab = floctab, loctab_entry = curr_loctab_entry):
        # flush reloff data into .cdi_floctab
        floctab.append('\t.long {}\n'.format(hex(loctab_entry.num_f_reloffs)))
        floctab.append('\t.long {}\n'.format(hex(loctab_entry.num_fret_reloffs)))
        floctab.append(loctab_entry.f_reloffs)
        floctab.append(loctab_entry.fret_reloffs)
        loctab_entry.f_reloffs = loctab_entry.fret_reloffs = ''
        loctab_entry.num_f_reloffs = loctab_entry.num_fret_reloffs = 0
    
    asm_dest.write('\t.section .cdi_ftypetab, "a", @progbits\n')
    write_typetab(asm_dest, functs, 'ftype', on_type_used, on_type_exhausted)
    
    asm_dest.write('\t.section .cdi_floctab, "a", @progbits\n')
    asm_dest.write('\t.align 4\n')
    for text in floctab:
        asm_dest.write(text)

    # terminate the loctab with a long NULL so the loader knows when the type
    # table ends
    asm_dest.write('\t.long 0x0\n')


    curr_loctab_entry = FploctabEntry()
    def on_type_used(fptr_site, loctab_entry = curr_loctab_entry):
        loctab_entry.site_reloffs += ('\t.long 0x0\n"_CDIX_RREL32_0__CDIX_FPTR_{}_{}":\n'
                .format(fix_label(fptr_site.enclosing_funct_uniq_label),
                    fptr_site.indir_call_id))
        loctab_entry.num_site_reloffs += 1

    fploctab = []
    def on_type_exhausted(fploctab = fploctab, loctab_entry = curr_loctab_entry):
        fploctab.append('\t.long {}\n'.format(hex(loctab_entry.num_site_reloffs)))
        fploctab.append(loctab_entry.site_reloffs)

        loctab_entry.site_reloffs = ''
        loctab_entry.num_site_reloffs = 0

    asm_dest.write('\t.section .cdi_fptypetab, "a", @progbits\n')
    if fptr_sites:
        write_typetab(asm_dest, fptr_sites, 'fptype', 
                on_type_used, on_type_exhausted)
        asm_dest.write('\t.section .cdi_fploctab, "a", @progbits\n')
        asm_dest.write('\t.align 4\n')
        for text in fploctab:
            asm_dest.write(text)
    else:
        asm_dest.write('\t.byte 0x0\n')
        asm_dest.write('\t.section .cdi_fploctab, "a", @progbits\n')
        asm_dest.write('\t.align 4\n')

    # terminate the loctab with a long NULL so the loader knows when the type
    # table ends
    asm_dest.write('\t.long 0x0\n')
    

def write_typetab(asm_dest, type_objs, type_attr, on_type_used, on_type_exhausted):
    """Writes a type table to asm_dest

    type_objs is a list of objects that have function types attached at an
    attribute with name type_attr.

    on_type_used is called with a type_obj every time a type_obj's type is 
    added to the table or matches with another type in the table

    on_type_exhausted is called every time all type_objs's with a type have been 
    added to the table. Once a type has been added to the table, all type_objs
    that have a matching type must be examined before adding the next type. This
    means that at any give time, only one type is under examination
    """

    # prioritize typestring size when sorting
    def type_compare(type1, type2):
        if len(type1) != len(type2):
            return len(type1) - len(type2)
        else:
            return cmp(type1, type2)

    type_objs.sort(key=operator.attrgetter(type_attr), cmp=type_compare)

    # Strings are written with increasing size. This is the 
    # length accumulated so far. 
    len_acc = 0

    # handle the first specially
    curr_type = ''
    if type_objs:
        curr_type = getattr(type_objs[0], type_attr)
        len_acc = len(curr_type)

        # the len must be stored in a single byte
        byte_hex = ''
        if len_acc < 255:
            byte_hex = hex(len_acc)
        else:
            byte_hex = '0xff'
        asm_dest.write('\t.byte {}\n'.format(byte_hex))
        asm_dest.write('\t.string "{}"\n'.format(curr_type))

    for type_obj in type_objs:
        if curr_type != getattr(type_obj, type_attr):
            on_type_exhausted()

            curr_type = getattr(type_obj, type_attr)
            len_diff = len(curr_type) - len_acc
            len_acc = len(curr_type)

            # we only store one byte's worth of length difference
            if len_diff < 255:
                byte_hex = hex(len_diff)
            else:
                byte_hex = '0xff'
            asm_dest.write('\t.byte {}\n'.format(byte_hex))
            asm_dest.write('\t.string "{}"\n'.format(curr_type))
        on_type_used(type_obj)
    on_type_exhausted()
def fix_label(label):
    return label.replace('@PLT', '').replace('/', '__').replace('.fake.o', '.cdi.s')

