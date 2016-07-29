import sys
from eprint import eprint

class AsmFileDescription:
    def __init__(self, name):
        self.filename = name

        # these unique define functions because we have their filename (above)
        self.funct_names = [] 

    def check_filename(self):
        if self.filename[-2:] != '.s':
            eprint('error: non-assembly file passed:', self.filename)
            sys.exit(1)
        elif len(self.filename) >= len('.cdi.s') and self.filename[-6:] == '.cdi.s':
            eprint('error: cdi-assembly file passed:', self.filename)
            sys.exit(1)

    def src_filename(self):
        return self.filename[:-2] + '.c'


def goto_next_funct(asm_file, line_num, dwarf_loc):
    """Moves file ptr to first instr of next funct. Returns name of said funct

    Precisely, the file ptr points to the line after '.LFB*' where * is a digit
    Returns '' if no functions are left in the file
    """

    prev_label = ''
    globl_decl = ''

    asm_line = asm_file.readline()
    line_num += 1
    while asm_line:
        update_dwarf_loc(asm_line, dwarf_loc)
        # ignore empty lines
        if asm_line != '\n':
            first_word = asm_line.split()[0]

            if first_word[-1] == ':':
                if (first_word[:len('.LFB')] == '.LFB' 
                        and first_word[len('.LFB'):-1].isdigit()):
                    return prev_label, line_num, prev_label == globl_decl
                else:
                    prev_label = first_word[:-1]
            elif first_word == '.globl':
                globl_decl = decode_line(asm_line, False)[2]

        asm_line = asm_file.readline()
        line_num += 1

    return '', line_num, False

class DwarfSourceLoc:
    # internal, don't touch
    _filename_dict = dict()

    def __init__(self):
        self.filenum = -1
        self.line_num = -1
        self.col_num = -1

    def map_filename(self, filenum, filename):
        self._filename_dict[filenum] = filename

    def filename(self):
        if self.filenum not in self._filename_dict:
            eprint('warning: undefined filenumber: ' + str(self.filenum))
            return '?'
        return self._filename_dict[self.filenum]

    def __str__(self):
        return self.filename() + ':' + str(self.line_num) + ':' + str(self.col_num)

    def valid(self):
        return self.filenum >= 0 and self.line_num >= 0 and self.col_num >= 0

    @staticmethod
    def wipe_filename_mapping():
        DwarfSourceLoc._filename_dict.clear()

def update_dwarf_loc(asm_line, dwarf_loc):
    """Checks for a .loc or .file directive then updates location if needed
    
    Assumes there is no comment before the key symbol
    """

    # at most 4 words needed: ".loc filenum line_num col_num"
    asm_list = asm_line.split(None, 4)
    if not asm_list:
        return
    elif asm_list[0] == '.loc':
        dwarf_loc.filenum = int(asm_list[1])
        dwarf_loc.line_num = int(asm_list[2])
        dwarf_loc.col_num = int(asm_list[3])
    elif asm_list[0] == '.file' and asm_list[1].isdigit():
        dwarf_loc.map_filename(int(asm_list[1]), asm_list[2].strip('"'))

def decode_line(asm_line, comment_continues):
    """Decodes the asm_line into key_symbols, an argument_string and label list

    key symbols are the first non-label in a line. There might not be a 
    key symbol in the line. See:
    https://sourceware.org/binutils/docs/as/Statements.html#Statements

    comment_continues specifies whether asm_line is a continuation of a 
    comment from a previous line

    Returns (labels[], key_symbol_string, argument_string, comment_continues)
    as a tuple

    Returns '' or [] when a key_symbol or the like is missing
    """
    
    commentless_asm_line, comment_continues = (
            remove_comments(asm_line, comment_continues))
    words = commentless_asm_line.split()

    key_symbol = ''
    labels = []
    args_list = []
    
    key_symbol_found = False
    for word in words:
        if not key_symbol_found:
            if word[-1] == ':':
                labels.append(word[:-1])
            else:
                key_symbol = word
                key_symbol_found = True
        else:
            args_list.append(word)
    arg_str = ' '.join(args_list)

    return labels, key_symbol, arg_str, comment_continues

def remove_comments(asm_line, comment_continues):
    """Finds comments in asm_line and returns a commentless version

    comment_continues specifies whether asm_line is a continuation of 
    a comment from a previous line

    Also returns whether or not asm_line starts a comment that continues onto
    the next line. Returns are in the form:

    (commentless_asm_line, whether_comment_continues_onto_next_line)
    """

    if comment_continues:
        comment_end_index = asm_line.find('*/')
        if comment_end_index == -1:
            return '', True
        else:
            asm_line_fixed = asm_line[comment_end_index + len('*/'):]
            return remove_comments(asm_line_fixed, False)

    elif '/*' in asm_line:
        comment_start_index = asm_line.find('/*')
        # gracefully avoid edge case where '/*/' is present
        comment_end_index = asm_line.find('*/', comment_start_index + len('/*'))

        if comment_end_index == -1:
            # the comment continues onto the next line so this must be the 
            # last comment. Hence asm_line is completely fixed after this
            asm_line_fixed = asm_line[:comment_start_index]
            return asm_line_fixed, True
        else:
            asm_line_fixed = (asm_line[:comment_start_index]
                    + asm_line[comment_end_index + len('*/'):])
            return remove_comments(asm_line_fixed, comment_continues) 

    elif '#' in asm_line:
        comment_start_index = asm_line.find('#')
        asm_line_fixed = asm_line[:comment_start_index] + '\n'
        return remove_comments(asm_line_fixed, comment_continues) 

    else:
        return asm_line, False


