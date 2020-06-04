from __future__ import print_function
import sys

# By default, print to sys.stderr
STDERR = sys.stderr
STDOUT = sys.stdout
VERBOSE = False
QUIET = False

# Credit:
# http://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
def eprint(*args, **kwargs):
    if not QUIET:
        print(*args, file=STDERR, **kwargs)

def vprint(*args, **kwargs):
    if not QUIET:
        print(*args, file=STDOUT, **kwargs)

def vvprint(*args, **kwargs):
    if VERBOSE and not QUIET:
        print(*args, file=STDOUT, **kwargs)

# always prints
def fatal_print(*args, **kwargs):
    print(*args, file=STDERR, **kwargs)

