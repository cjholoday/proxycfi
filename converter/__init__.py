import os, sys

script_dir = os.path.dirname(os.path.realpath(__file__))

# find the top level directory, which is named 'cdi'
top = script_dir
while not top.endswith('/cdi') and top != '/':
    top = os.path.dirname(top)

# we must add the top level directory to the path so that scripts in this 
# directory can access modules from above. Normally running scripts with the
# '-m' option would suffice. However, since cdi-gcc calls cdi-as.py and cdi-ld.py
# as if they were the GNU assembler and the GNU linker, we cannot use the '-m'
# option to run them as subpackages. While the converter doesn't suffer from this
# problem consistency is important. All parts of the CDI toolchain will therefore
# add the top level directory to the path.
if top.endswith('/cdi'):
    sys.path.append(top)
