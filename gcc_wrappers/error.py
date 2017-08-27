import __init__
from common.eprint import eprint
import sys
import subprocess

restore_original_objects_fptr = None
raw_ld_spec = None
file_deleted_on_error = None
def fatal_error(message):
    """Prints error message with the spec passed to cdi-ld.py and exits with error

    Restores objs to their state as of before cdi-ld allowing for 
    easy debugging. For this to work, error.restore_original_objects_fptr
    must be set
    """
    eprint('\n----------------------------------------------\n'
            'cdi-ld: error: {}'.format(message))
    eprint('\nSpec passed to cdi-ld.py: {}'.format(' '.join(raw_ld_spec)))
    if restore_original_objects_fptr:
        restore_original_objects_fptr()

    if file_deleted_on_error:
        subprocess.check_call(['rm', file_deleted_on_error])

    sys.exit(1)
