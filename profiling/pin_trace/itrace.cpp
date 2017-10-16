/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include "pin.H"
#include <cstdio>
#include <map>
using namespace std;

KNOB<string>    KnobItraceFile(KNOB_MODE_WRITEONCE, "pintool", "i", "itrace.out", "specify output file name for instruction trace");
// KNOB<string>    KnobMtraceFile(KNOB_MODE_WRITEONCE, "pintool", "m", "mtrace.out", "specify output file name for mtrace");
KNOB<ADDRINT>   KnobMemStartAddress(KNOB_MODE_WRITEONCE, "pintool", "a", "0x0", "memory image start address");
KNOB<ADDRINT>   KnobMemSize(KNOB_MODE_WRITEONCE, "pintool", "s", "0x0", "memory image size");

//map to keep the disasm representation for decoded instructions
map<ADDRINT, string> decoded;

FILE *itrace;
//to number the itrace line
UINT64 idx;


inline bool inside(ADDRINT ip)
{
    return (KnobMemStartAddress.Value() <= (ADDRINT)(ip)) && ((ADDRINT)(ip) < KnobMemStartAddress.Value() + KnobMemSize.Value());
}

// This function is called before every instruction in loaded image code is executed
VOID printip(VOID *ip)
{
    ++idx;
    fprintf(itrace, "%04lu,0x%016lx,\"%s\"\n", idx, (UINT64)(ip), decoded[(ADDRINT)(ip)].c_str());
}



// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{

    ADDRINT ip = INS_Address(ins);//(ADDRINT)PIN_GetContextReg( ctxt, REG_INST_PTR);
    if (inside(ip)){
        // Insert a call to printip before every instruction, and pass it the IP
        string disasm = INS_Disassemble(ins);
        decoded[ip] = disasm;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
    }


}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    fclose(itrace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    printf("Instruction Trace PIN Tool started!\n");
    // Initialize pin&symbol manager
    if (PIN_Init(argc, argv)) return Usage();

    printf("-I-: Using the following trace config:\n");
    printf("itrace filename:   %s\n", KnobItraceFile.Value().c_str());
    // printf("mtrace filename:   %s\n", KnobMtraceFile.Value().c_str());
    // printf("mem start address: 0x%016lx\n", (UINT64)(KnobMemStartAddress.Value()));
    // printf("mem size:          0x%016lx\n", (UINT64)(KnobMemSize.Value()));

    itrace = fopen(KnobItraceFile.Value().c_str(), "wt");
    // mtrace = fopen(KnobMtraceFile.Value().c_str(), "wt");
    idx = UINT64_MAX;
    fprintf(itrace, "step,iptr,asm\n");
    // fprintf(mtrace, "step,iptr,mode,address,size\n");

    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
