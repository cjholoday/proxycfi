#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "uthash.h"

/*
 * Instrumentation
 *
 * When compiled with a c program and with -finstrument_functions enabled,
 * this file generates a trace of the control flow in a program. On entering
 * a function, that function's id will be printed to trace.out. On exiting any
 * function 0 will be printed to trace.out. All function id's are > 0. 
 *
 * What is a function id? A function id is a unique number assigned to each 
 * function. While the functions address is unique, it is also a lot to print
 * with every function call. A function id is therefore used instead to save
 * on the memory used by instrumenting applications. It really is necessary for
 * long executions.
 *
 * Function id's are assigned on a first come first server basis. The first function
 * to be called receives 1, the second function 2, and so on. A mapping from 
 * function id to function address is printed in trace_table.out
 *
 * trace.out and trace_table.out are the two file outputted by instrumentation
 * and they can be found in the working directory of where the executable is run
 *
 * Function names are retrieved from the executable by inspecting debugging 
 * information with function addresses. Compiling with -g is therefore
 * necessary to get the function names. See diff_trace.py and addr_translation.py
 * for ways to use trace.out and trace_table.out
 *
 * To use this in a build system like automake, configure with: 
 * CFLAGS="-Wl,/absolute/path/to/instrumentation.o -g -finstrument-functions"
 */

static FILE *trace_file = NULL;
static FILE *trace_table_file = NULL;
static int reduced_id_faucet = 1;


// Needed for uthash
typedef struct {
    void *addr;
    unsigned reduced_id;
    UT_hash_handle hh;
} FunctAddr;

static FunctAddr *faddr_hash_table = NULL;

// open trace.out and trace_table.out before main executes
static void __attribute__((constructor)) __attribute__((no_instrument_function))
instrumentation_constructor() {
    trace_file = fopen("trace.out", "wb");
    if (!trace_file) {
        exit(1);
    }

    trace_table_file = fopen("trace_table.out", "wb");
    if (!trace_table_file) {
        exit(1);
    }
}

void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *this_fn, void *call_site)
{
    FunctAddr *faddr = (FunctAddr*)malloc(sizeof(FunctAddr));
    faddr->addr = this_fn;

    FunctAddr *existing_elt = NULL;
    HASH_FIND_PTR(faddr_hash_table, &this_fn, existing_elt);
    if (existing_elt) {
        faddr->reduced_id = existing_elt->reduced_id;
    }
    else {
        faddr->reduced_id = reduced_id_faucet++;
        HASH_ADD_PTR(faddr_hash_table, addr, faddr);
        fprintf(trace_table_file, "%d %p\n", faddr->reduced_id, this_fn);
    }

    fprintf(trace_file, "%d\n", faddr->reduced_id);
}

void __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *this_fn, void *call_site)
{
    FunctAddr *existing_elt = NULL;
    HASH_FIND_PTR(faddr_hash_table, &this_fn, existing_elt);
    if (!existing_elt) {
        fprintf(stderr, "instrumentation error: "
                "Function adddress not recorded in hash table");
        exit(1);
    }

    fprintf(trace_file, "0\n");
}

