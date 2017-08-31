import __init__

import os

def cdi_abort(sled_id, asm_filename, dwarf_loc, try_callback_sled, options):
    """Return (code, data) that allows for aborting with sled-specific info.
    
    Code should be placed at the end of a return/call sled. data should be 
    placed away from code so that the verifier works correctly.

    code is a list with two strings in it. The first stores debug information
    into %r11 and the second either jumps to _CDI_abort or is the empty string
    """


    loc_str = asm_filename.replace('.fake.o', '.cdi.s')
    if dwarf_loc.valid():
        loc_str = '{}:{}/{}'.format(str(dwarf_loc), os.path.basename(os.getcwd()), loc_str)

    cdi_abort_code = []
    cdi_abort_data = ''
    if options['--shared-library']:
        # Load effective address of sled debug info into %r11. We let gen_cdi.asm.py
        # decide what to do after getting the sled info because the action
        # depends on the type of sled we're in
        cdi_abort_code.append('\t.byte 0x4c\n')
        cdi_abort_code[0] += '\t.byte 0x8d\n'
        cdi_abort_code[0] += '\t.byte 0x1d\n'
        cdi_abort_code[0] += '\t.long 0x00\n'
        cdi_abort_code[0] += '"_CDIX_RREL32_{}_{}":\n'.format(
                str(sled_id), '_CDIX_SLED_' + str(sled_id))
        cdi_abort_code.append('')
    else:
        cdi_abort_code.append('\tmovq\t $_CDIX_SLED_' + str(sled_id) + ', %r11\n')

        # jmp to _CDI_abort. We need to reserve exactly 13 bytes in total because
        # it may be overwritten with a jmp to a function pointer sled. We do the 
        # relocation ourselves because 'as' may optimize the jmp to _CDI_abort into
        # less than 5 bytes
        cdi_abort_code.append('\t.byte 0xe9\n')
        cdi_abort_code[1] += '\t.long 0x0\n'
        cdi_abort_code[1] += '_CDIX_RREL32_{}_{}:\n'.format(sled_id, '_CDI_abort')
        cdi_abort_code[1] += '\tnop\n' * (13 - 5)

    cdi_abort_msg = loc_str + ' id=' + str(sled_id)
    cdi_abort_data += '_CDIX_SLED_' + str(sled_id) + ':\n'
    cdi_abort_data += '\t.quad\t' + str(len(cdi_abort_msg)) + '\n'
    cdi_abort_data += '\t.string\t"' + cdi_abort_msg + '"\n'

    return (cdi_abort_code, cdi_abort_data)

