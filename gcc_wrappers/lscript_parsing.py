import string
import sys

from eprint import eprint
import error

blacklisted_commands = ['ENTRY', 'MEMORY', 'SECTIONS']
def extract_lscript_spec_entries(lscript_path):
    """Returns a list of spec entries implicitly created from the linker script"""

    implicit_spec_entries = []
    for command, command_body in get_lscript_commands(lscript_path):
        print command, '::', ' '.join(implicit_spec_entries)
        print command_body
        print lscript_path
        #if command == 'SEARCH_DIR':
        #    implicit_spec_entries.append('-L' + command_body.strip().strip('"'))
        #elif command in ('GROUP', 'INPUT'): # add archives / shared libs
        #    if command == 'GROUP':
        #        implicit_spec_entries.append('--start-group')


        #    pass
        #elif command == 'INCLUDE': # specifies linker script
        #    implicit_spec_entries += get_lscript_commands(command_body.strip().strip('"'))
        #elif command in blacklisted_commands:
        #    fatal_error("linker spec includes blacklisted command '{}'"
        #            .format(command))
        #else:
        #    fatal_error("linker spec includes unhandled command '{}'"
        #            .format(command))
    sys.exit(0)


class LinkerScriptSyntaxError(Exception):
    def __init__(self, msg, text_idx):
        self.msg = msg
        self.text_idx = tex_idx

def get_lscript_commands(lscript_path):
    """Returns a generator for (command, command body) tuples"""

    lscript_text = ''
    with open(lscript_path, 'rb') as linker_script:
        lscript_text = linker_script.read()

    try:
        input_is_required = False
        text = enumerate(lscript_text)
        for idx, char in text:
            if char in string.whitespace + ';':
                continue
            elif char == '/':
                input_is_required = True
                idx, char = text.next()
                if char != '*':
                    syntax_error(lscript_text, idx, "expected token '*'", lscript_path)
                prev_char = char
                while prev_char != '*' or char != '/':
                    prev_char = char
                    idx, char = text.next()
                input_is_required = False

            elif char in string.letters:
                input_is_required = True
                command = ''
                while char in string.letters + string.digits + '_':
                    command += char
                    idx, char = text.next()
                while char in string.whitespace:
                    idx, char = text.next()
                if char not in ['(', '{']:
                    syntax_error(lscript_text, idx, "expected '(' or '{' after command", lscript_path)

                body_markers = ()
                if char == '(':
                    body_markers = ('(', ')')
                else:
                    body_markers = ('{', '}')

                # how many layers deep we are in the command
                nested_count = 1

                char = command_body = ''
                while nested_count > 0:
                    command_body += char
                    idx, char = text.next()
                    if char == body_markers[0]:
                        nested_count += 1
                    elif char == body_markers[1]:
                        nested_count -= 1
                input_is_required = False
                yield command, command_body
            else:
                syntax_error(lscript_text, idx, 'expected command', lscript_path)
    except StopIteration:
        if input_is_required:
            syntax_error(lscript_text, -1, "linker script ends prematurely", lscript_path)

def syntax_error(lscript_text, error_idx, msg, lscript_path):
    reversed_error_idx = len(lscript_text) - error_idx - 1
    reversed_line_begin = lscript_text[::-1].find('\n', reversed_error_idx) - 1
    line_begin = len(lscript_text) - reversed_line_begin - 1

    line_end = lscript_text.find('\n', error_idx)
    if line_begin == -1:
        line_begin = 0

    error_line_num = lscript_text.count('\n', 0, error_idx) + 1

    error_line = ''
    if line_end == -1:
        error_line = lscript_text[line_begin:]
    else:
        error_line = lscript_text[line_begin:line_end]
    caret_idx = error_idx - line_begin

    eprint("cdi-ld: error: failed parsing linker script '{}' on line {}"
            .format(lscript_path, error_line_num))
    eprint('\t' + error_line)
    eprint('\t' + caret_idx * ' ' + '^')
    eprint('syntax error: ' + msg)
    sys.exit(1)
