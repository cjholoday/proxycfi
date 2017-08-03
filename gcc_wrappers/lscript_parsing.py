import __init__

import string
import sys
import collections

from common.eprint import eprint
from error import fatal_error

class LinkerScriptSyntaxError(Exception):
    def __init__(self, msg, text_idx):
        self.msg = msg
        self.text_idx = tex_idx

class LinkerScriptReader():
    """A class that encapsulates reading from the linker script file."""
    class Location():
        def __init__(self, lscript_path, line_num, col_idx):
            self.path = lscript_path
            self.line_num = line_num
            self.col_idx = col_idx

    class EndOfFile(Exception):
        pass

    def __init__(self, lscript_path):
        self.lscript_path = lscript_path
        self.char_buffer = collections.deque()
        self.loc_buffer = collections.deque()
        self.lscript = open(lscript_path, 'r')
        self.consumed_loc = LinkerScriptReader.Location(lscript_path, 1, 0)
        self.consumed_char = ''

    def consume_n(self, count):
        """Consumes n characters and return the last. Returns '' on EOF"""
        try:
            self.buffer_n(count)
        except LinkerScriptReader.EndOfFile:
            return ''

        for i in xrange(count - 1):
            self.char_buffer.popleft()
            self.loc_buffer.popleft()
        self.consumed_loc = self.loc_buffer.popleft()
        self.consumed_char = self.char_buffer.popleft()
        return self.consumed_char

    def peek_n(self, count):
        """Returns n characters ahead of the current location. Returns '' on EOF"""
        try:
            self.buffer_n(count)
        except LinkerScriptReader.EndOfFile:
            return ''
        return self.char_buffer[count - 1]


    def loc_n(self, count):
        """Returns the location of the character n consumptions ahead, Returns None on EOF"""
        try:
            self.buffer_n(count)
        except LinkerScriptReader.EndOfFile:
            return None
        return self.loc_buffer[count - 1]

    def consume_whitespace(self):
        """Consumes until the peek_n(1) isn't whitespace"""
        while self.peek_n(1) in string.whitespace:
            if self.consume_n(1) == '':
                return
        
    def buffer_n(self, count):
        """Buffers n characters ahead INCLUDING ALREADY BUFFERED CHARS
        
        Throws EndOfFile if the buffer cannot be filled because of EOF
        """
        assert count > 0
        
        prev_char = self.consumed_char
        prev_loc = self.consumed_loc
        if self.char_buffer:
            prev_char = self.char_buffer[-1]
            prev_loc = self.loc_buffer[-1]

        while len(self.char_buffer) < count:
            char = self.lscript.read(1)
            if char == '':
                raise LinkerScriptReader.EndOfFile
            if prev_char == '\n':
                self.loc_buffer.append(LinkerScriptReader.Location(prev_loc.path,
                    prev_loc.line_num + 1, 0))
            else:
                self.loc_buffer.append(LinkerScriptReader.Location(prev_loc.path,
                    prev_loc.line_num, prev_loc.col_idx + 1))
            self.char_buffer.append(char)
            prev_char = char
            prev_loc = self.loc_buffer[-1]

blacklisted_commands = ['ENTRY', 'MEMORY', 'SECTIONS']
whitelisted_commands = ['OUTPUT_FORMAT']
def extract_spec_entries(lscript_path):
    """Returns a generator for (command, command body) tuples"""

    reader = LinkerScriptReader(lscript_path)

    spec_entries = []
    while reader.peek_n(1) != '':
        # invariant: at the start of every loop, we are parsing for the 
        # next command (if one exists)
        char = reader.consume_n(1)
        if char in string.whitespace + ';':
            continue
        elif char == '/':
            char = reader.consume_n(1)
            if char != '*':
                syntax_error(reader.consumed_loc, "expected token '*'")
            while not (reader.peek_n(1) == '*' and reader.peek_n(2) == '/'):
                if reader.consume_n(1) == '':
                    syntax_error(reader.consumed_loc, 'script ends in middle of comment')
            reader.consume_n(2)
        elif char in string.letters:
            command = char
            while reader.peek_n(1) in string.letters + string.digits + '_':
                command += reader.consume_n(1)

            reader.consume_whitespace()
            if reader.peek_n(1) not in '({':
                syntax_error( "expected '(' or '{' after command", lscript_path)

            # Handle each command individually
            if command == 'SEARCH_DIR':
                spec_entries.append(parse_path(reader))
            elif command in ('GROUP', 'INPUT'): # add archives / shared libs
                if command == 'GROUP':
                    spec_entries.append('--start-group')
                spec_entries += parse_input_cmd_body(reader)
                if command == 'GROUP':
                    spec_entries.append('--end-group')
            elif command == 'INCLUDE': # specifies linker script
                spec_entries += extract_spec_entries(parse_path(reader))
            elif command in blacklisted_commands:
                fatal_error("linker spec includes blacklisted command '{}'"
                        .format(command))
            elif command in whitelisted_commands:
                skip_command_body(reader)
            else:
                fatal_error("linker spec includes unhandled command '{}'"
                        .format(command))
        else:
            syntax_error(reader.consumed_loc, 'expected command')
    return spec_entries

def parse_input_cmd_body(reader):
    """Given LinkerScriptReader on GROUP or INPUT, returns the associated spec entries
    
    The reader should point at '(' or '{'. That is,reader.peek_n(1) in '({'
    """
    reader.consume_n(1)
    reader.consume_whitespace()

    spec_entries = []
    i = 0
    while reader.peek_n(1) != ')':
        if reader.peek_n(1) == 'A':
            for expected_char in 'AS_NEEDED':
                if reader.consume_n(1) != expected_char:
                    syntax_error(reader.consumed_loc, 'expected command AS_NEEDED')
            reader.consume_whitespace()
            if reader.consume_n(1) != '(':
                syntax_error(reader.consumed_loc, "expected '(' after AS_NEEDED")

            spec_entries.append('--as-needed')
            reader.consume_whitespace()
            while reader.peek_n(1) != ')':
                spec_entries.append(parse_path(reader))
                reader.consume_whitespace()
            reader.consume_n(1)
            spec_entries.append('--no-as-needed')
        else:
            spec_entries.append(parse_path(reader))
        reader.consume_whitespace()

    reader.consume_n(1)
    return spec_entries

def parse_path(reader):
    """Returns the path pointed at by the LinkerScriptReader
    
    The path may or may not be quoted. The path returned is unquoted
    """
    path = ''
    reader.consume_whitespace()
    if reader.peek_n(1) == '"': # path is quoted
        reader.consume_n(1)
        while reader.peek_n(1) != '"':
            if reader.peek_n(1) == '':
                syntax_error(reader.consumed_loc, 'EOF inside of quotation')
            path += reader.consume_n(1)
        reader.consume_n(1)
    else: # path is unquoted
        while reader.peek_n(1) in string.letters + string.digits + '-._/':
            if reader.peek_n(1) == '':
                break # cannot rule out the path is at EOF
            path += reader.consume_n(1)
    return path

def skip_command_body(reader):
    """Consumes all characters for a command body.

    LinkerScriptReader should be pointing at the opening '(' or '{'
    i.e. peek_n(1) in '({'
    """
    body_markers = ()
    if reader.consume_n(1) == '(':
        body_markers = ('(', ')')
    else:
        body_markers = ('{', '}')

    nested_count = 1
    while nested_count > 0:
        char = reader.consume_n(1)
        if char == '':
            syntax_error(reader.consumed_loc, 'script ends in command body')
        elif char == body_markers[0]:
            nested_count += 1
        elif char == body_markers[1]:
            nested_count -= 1


def syntax_error(location, msg):
    error_line = ''
    with open(location.path, 'r') as lscript:
        for i, line in enumerate(lscript):
            if i + 1 == location.line_num:
                error_line = line
                break
    fatal_error("failed parsing linker script '{}' on line {}\n{}\n{}\n{}"
            .format(location.path, location.line_num, 
                '  ' + error_line[:-1],
                '  ' + location.col_idx * ' ' + '^',
                'syntax_error: ' + msg))
