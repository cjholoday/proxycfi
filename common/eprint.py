from __future__ import print_function
import sys

# By default, print to sys.stderr
STDERR = sys.stderr
STDOUT = sys.stdout
VERBOSE = True

# Credit:
# http://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def eprint(*args, **kwargs):
    if VERBOSE:
        print(*args, file=STDERR, **kwargs)

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, file=STDOUT, **kwargs)

def fatal_print(*args, **kwargs):
    print(*args, file=STDERR, **kwargs)

