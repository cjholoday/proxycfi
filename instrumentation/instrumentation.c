#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "uthash.h"

static FILE *trace_file = NULL;
static FILE *trace_table_file = NULL;
static int reduced_id_faucet = 1;

typedef struct {
    void *addr;
    unsigned reduced_id;
    UT_hash_handle hh;
} FunctAddr;

static FunctAddr *faddr_hash_table = NULL;

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

