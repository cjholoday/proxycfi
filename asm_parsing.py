class AsmFileDescription:
    def __init__(self, name):
        self.name = name
        self.funct_names = []

def goto_next_funct(asm_file):
    """Moves file pointer to next funct label. Return true if no functs left"""

    return True

def key_symbol(asm_line):
    """Returns the key symbol of string asm_line. Returns '' if there is none
    
    key_symbols are the first non-label in a line. There might not be a 
    key symbol in the line. See:
    https://sourceware.org/binutils/docs/as/Statements.html#Statements
    """
    pass

def decode(asm_line, return_labels = True):
    """Returns (labels[], key_symbol, argument_string) as a tuple
    
    If return_labels is set to false, then decode returns a tuple of the form:
        (key_symbol, argument_string)

    Return '' or [] when a key_symbol or the like is missing
    """
    pass
