#ifndef CDI_H
#define CDI_H

/* shotgun the dependencies 
 * (c-typeck.c dependencies) intersect (c-parser.c dependencies)
 */
#include "c-family/c-objc.h"
#include "c-lang.h"
#include "config.h"
#include "coretypes.h"
#include "c-tree.h"
#include "function.h"
#include "gimple-expr.h"
#include "gomp-constants.h"
#include "omp-low.h"
#include "stor-layout.h"
#include "system.h"
#include "target.h"
#include "trans-mem.h"
#include "varasm.h"

/* Start here.
 *
 * Only c-parser.c and c-typeck.c have been modified. A simple search with 'cdi'
 * will hit every area of code that has been changed. Function definitions for
 * CDI can be found in cdi.c, which is #included'd in c-parser.c so that the 
 * existing build structure won't shift
 *
 * Function type information and function pointer type information are dropped
 * into the files [src].ftypes and [src].fptypes where [src] is the source 
 * file in which the function definition / function pointer was found. These
 * files are created in the directory at which gcc is run.
 *
 * NOTE: All [src].ftypes and [src].fptypes files need to be deleted before
 * compilation begins. Currently, this must be done outside of cdi-gcc, perhaps 
 * in the makefile of the project being built.
 */

/*
 * Obtain the correct file to print to. If the typefile has already been 
 * created, or an error occurs, NULL is returned instead. Be careful to check
 * the return value!
 */
FILE *cdi_fptype_file();
FILE *cdi_ftype_file();

/* Prints the the location and mangling of a function declaration 
 * Format:
 *      <filename>:<line #>:<col #>:<funct name> <function signature>>
 * 
 * See cdi_print_funct_sig for details on mangling
 */
void cdi_print_funct_decl_info(FILE *typefile, tree funct_tree, location_t loc);
/*
 * Like cdi_print_funct_decl_info but the function name isn't printed in the
 * mangling because the fp can go to more than one function
 *
 * Format:
 *      <filename>:<line #>:<col #>:<enclosing function> <mangling>
 */
void cdi_print_fp_info(FILE *typefile, tree fp_tree, location_t loc);

/*
 * Mangles a function or function declaration and then prints to typefile 
 * without the function name included
 * If funct_tree is a function decl then its source name is printed in the
 * mangling.
 *
 * Functions are mangled according to the gnu c++ convention except that
 * the return type is prefixes the C++ mangling. Format:
 *
 *      <return_type>_<GNU C++ mangling>
 */
void cdi_print_funct_sig(FILE *typefile, tree funct_tree, location_t loc);

/*
 * print <filename>:<line #>:<col #>
 */
void cdi_print_loc(FILE *stream, location_t loc);
void cdi_warning_at(location_t loc, const char *msg);

/* 
 * Use before calling cdi_print_fp_info to tell it whether the current token
 * is acting as a function
 */
void cdi_set_function_ahead(bool is_ahead);
void cdi_print_arg_types(FILE *typefile, tree funct_tree, location_t loc);

/*
 * print the type as it appears in mangling
 */
void cdi_print_type(FILE* stream, tree type, location_t loc);

/* This functions taken from the C++ implementation
 *
 * The builtin types are defined as follows
 * Source: (http://mentorembedded.github.io/cxx-abi/abi.html#mangling)
 * <builtin-type> ::= v  # void
 *                ::= w  # wchar_t
 *                ::= b  # bool
 *                ::= c  # char
 *                ::= a  # signed char
 *                ::= h  # unsigned char
 *                ::= s  # short
 *                ::= t  # unsigned short
 *                ::= i  # int
 *                ::= j  # unsigned int
 *                ::= l  # long
 *                ::= m  # unsigned long
 *                ::= x  # long long, __int64
 *                ::= y  # unsigned long long, __int64
 *                ::= n  # __int128
 *                ::= o  # unsigned __int128
 *                ::= f  # float
 *                ::= d  # double
 *                ::= e  # long double, __float80
 *                ::= g  # __float128
 *                ::= z  # ellipsis
 *                ::= Dd # IEEE 754r decimal floating point (64 bits)
 *                ::= De # IEEE 754r decimal floating point (128 bits)
 *                ::= Df # IEEE 754r decimal floating point (32 bits)
 *                ::= Dh # IEEE 754r half-precision floating point (16 bits)
 *                ::= Di # char32_t
 *                ::= Ds # char16_t
 *                ::= Da # auto
 *                ::= Dc # decltype(auto)
 *                ::= Dn # std::nullptr_t (i.e., decltype(nullptr))
 *                ::= u <source-name>    # vendor extended type
 */
void cdi_print_builtin_type(FILE *stream, tree type, location_t loc);

#endif
