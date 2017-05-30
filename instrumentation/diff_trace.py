#!/usr/bin/env python

import sys
import itertools
from eprint import eprint



executable_fname = sys.argv[1]
trace1 = open(sys.argv[2], 'r')
funct_table1 = open(sys.argv[3], 'r')

trace2 = open(sys.argv[4], 'r')
funct_table2 = open(sys.argv[5], 'r')

trace1_id_to_name = [None]
for line in funct_table1:
    funct_name = line.split(' ')[1]
    trace1_id_to_name.append(funct_name)

# this dict allows us to build a translation between trace1 id's and trace2 id's
trace2_name_to_id = dict()

trace2_id_to_name = [None]
for i, line in enumerate(funct_table2):
    funct_name = line.split(' ')[1]
    trace2_name_to_id[funct_name] = i + 1
    trace2_id_to_name.append(funct_name)

funct_table1.close()
funct_table2.close()

if len(trace1_id_to_name) != len(trace2_id_to_name):
    eprint('error: trace 1 and trace 2 have a different number of defined functions')
    eprint('trace1: {} defined functions'.format(len(trace1_id_to_name)))
    eprint('trace2: {} defined functions'.format(len(trace2_id_to_name)))
    sys.exit(1)

# id_translation converts from a trace1 id to a trace2 id
id_translation = [0] * len(trace1_id_to_name)
for funct_id1 in xrange(1, len(id_translation)):
    funct_name1 = trace1_id_to_name[funct_id1]
    funct_id2 = trace2_name_to_id[funct_name1]
    id_translation[funct_id1] = funct_id2


for id1, id2 in enumerate(id_translation):
    if id1 != id2:
        eprint('Order of initial invocation of functions differs. The traces will differ ')
        eprint('    (trace1 function id) -> (trace2 function id)')
        for id1, id2 in enumerate(id_translation):
            eprint('    {} -> {}'.format(id1, id2))
        break
            

backtrace = []
for line1, line2 in itertools.izip(trace1, trace2):
    funct_id1 = int(line1.strip())
    funct_id2 = int(line2.strip())
    if id_translation[int(funct_id1)] != funct_id2:
        eprint('Control flow diverged. Common Backtrace: ')
        for funct_name in reversed(backtrace):
            eprint('    {}'.format(funct_name))
        eprint('')

        called_function = trace1_id_to_name[funct_id1]
        if called_function == None:
            eprint('trace1 returns')
        else:
            eprint('trace1 calls {}'.format(called_function))

        called_function = trace2_id_to_name[funct_id2]
        if called_function == None:
            eprint('trace2 returns')
        else:
            eprint('trace2 calls {}'.format(called_function))

        sys.exit(1)

    if funct_id2 == 0:
        try:
            del backtrace[-1]
        except:
            eprint('Too many returns in trace!')
            sys.exit(1)
    else:
        backtrace.append(trace1_id_to_name[funct_id1])



