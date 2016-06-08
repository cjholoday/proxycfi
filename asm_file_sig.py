class AsmFileSignature:
    """Assembly File Signature: contains the asm file name and funct names"""
    def __init__(self, name):
        self.name = name
        self.funct_names = []
