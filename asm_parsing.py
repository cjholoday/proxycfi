import sys

class AsmFileDescription:
    def __init__(self, name):
        self.name = name
        self.funct_names = []

def goto_next_funct(asm_file, line_num):
    """Moves file ptr to first instr of next funct. Returns name of said funct

    Precisely, the file ptr points to the line after '.LFB*' where * is a digit
    Returns '' if no functions are left in the file
    """

    prev_label = ''

    asm_line = asm_file.readline()
    line_num += 1
    while asm_line:
        # ignore empty lines
        if asm_line != '\n':
            first_word = asm_line.split()[0]

            if (first_word[-1] == ':'):
                if (first_word[:len('.LFB')] == '.LFB' 
                        and first_word[len('.LFB'):-1].isdigit()):
                    return prev_label, line_num
                else:
                    prev_label = first_word[:-1]

        asm_line = asm_file.readline()
        line_num += 1

    return '', line_num


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

def is_label(word):
    """Returns true if word is a label.

    Labels are a string of alphanumeric characters that may begin with '.' or
    an alphabetic char but not a digit. '_' may appear anywhere in the string
    as well
    """

    if not word or word[0].isdigit():
        return False
    
    for c in word[1:]:
        if not c.isalnum() and not c == '_':
            return False
    return True

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


