/* Machine-dependent ELF dynamic relocation inline functions.  x86-64 version.
   Copyright (C) 2001-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Jaeger <aj@suse.de>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef dl_machine_h
#define dl_machine_h

#define ELF_MACHINE_NAME "x86_64"

#include <sys/param.h>
#include <sysdep.h>
#include <tls.h>
#include <dl-tlsdesc.h>
#include <cpu-features.c>
#include <dl-cdi.h>

/* Return nonzero iff ELF header is compatible with the running host.  */
static inline int __attribute__ ((unused))
elf_machine_matches_host (const ElfW(Ehdr) *ehdr)
{
  return ehdr->e_machine == EM_X86_64;
}


/* Return the link-time address of _DYNAMIC.  Conveniently, this is the
   first element of the GOT.  This must be inlined in a function which
   uses global data.  */
static inline ElfW(Addr) __attribute__ ((unused))
elf_machine_dynamic (void)
{
  /* This produces an IP-relative reloc which is resolved at link time. */
  extern const ElfW(Addr) _GLOBAL_OFFSET_TABLE_[] attribute_hidden;
  return _GLOBAL_OFFSET_TABLE_[0];
}


/* Return the run-time load address of the shared object.  */
static inline ElfW(Addr) __attribute__ ((unused))
elf_machine_load_address (void)
{
  /* Compute the difference between the runtime address of _DYNAMIC as seen
     by an IP-relative reference, and the link-time address found in the
     special unrelocated first GOT entry.  */
  extern ElfW(Dyn) _DYNAMIC[] attribute_hidden;
  return (ElfW(Addr)) &_DYNAMIC - elf_machine_dynamic ();
}

/* Set up the loaded object described by L so its unrelocated PLT
   entries will jump to the on-demand fixup code in dl-runtime.c.  */

static inline int __attribute__ ((unused, always_inline))
elf_machine_runtime_setup (struct link_map *l, int lazy, int profile)
{
  Elf64_Addr *got;
  extern void _dl_runtime_resolve_sse (ElfW(Word)) attribute_hidden;
  extern void _dl_runtime_resolve_avx (ElfW(Word)) attribute_hidden;
  extern void _dl_runtime_resolve_avx512 (ElfW(Word)) attribute_hidden;
  extern void _dl_runtime_profile_sse (ElfW(Word)) attribute_hidden;
  extern void _dl_runtime_profile_avx (ElfW(Word)) attribute_hidden;
  extern void _dl_runtime_profile_avx512 (ElfW(Word)) attribute_hidden;

  if (l->l_info[DT_JMPREL] && lazy)
    {
      /* The GOT entries for functions in the PLT have not yet been filled
	 in.  Their initial contents will arrange when called to push an
	 offset into the .rel.plt section, push _GLOBAL_OFFSET_TABLE_[1],
	 and then jump to _GLOBAL_OFFSET_TABLE_[2].  */
      got = (Elf64_Addr *) D_PTR (l, l_info[DT_PLTGOT]);
      /* If a library is prelinked but we have to relocate anyway,
	 we have to be able to undo the prelinking of .got.plt.
	 The prelinker saved us here address of .plt + 0x16.  */
      if (got[1])
	{
	  l->l_mach.plt = got[1] + l->l_addr;
	  l->l_mach.gotplt = (ElfW(Addr)) &got[3];
	}
      /* Identify this shared object.  */
      *(ElfW(Addr) *) (got + 1) = (ElfW(Addr)) l;

      /* The got[2] entry contains the address of a function which gets
	 called to get the address of a so far unresolved function and
	 jump to it.  The profiling extension of the dynamic linker allows
	 to intercept the calls to collect information.  In this case we
	 don't store the address in the GOT so that all future calls also
	 end in this function.  */
      if (__glibc_unlikely (profile))
	{
	  if (HAS_ARCH_FEATURE (AVX512F_Usable))
	    *(ElfW(Addr) *) (got + 2) = (ElfW(Addr)) &_dl_runtime_profile_avx512;
	  else if (HAS_ARCH_FEATURE (AVX_Usable))
	    *(ElfW(Addr) *) (got + 2) = (ElfW(Addr)) &_dl_runtime_profile_avx;
	  else
	    *(ElfW(Addr) *) (got + 2) = (ElfW(Addr)) &_dl_runtime_profile_sse;

	  if (GLRO(dl_profile) != NULL
	      && _dl_name_match_p (GLRO(dl_profile), l))
	    /* This is the object we are looking for.  Say that we really
	       want profiling and the timers are started.  */
	    GL(dl_profile_map) = l;
	}
      else
	{
	  /* This function will get called to fix up the GOT entry
	     indicated by the offset on the stack, and then jump to
	     the resolved address.  */
	  if (HAS_ARCH_FEATURE (AVX512F_Usable))
	    *(ElfW(Addr) *) (got + 2) = (ElfW(Addr)) &_dl_runtime_resolve_avx512;
	  else if (HAS_ARCH_FEATURE (AVX_Usable))
	    *(ElfW(Addr) *) (got + 2) = (ElfW(Addr)) &_dl_runtime_resolve_avx;
	  else
	    *(ElfW(Addr) *) (got + 2) = (ElfW(Addr)) &_dl_runtime_resolve_sse;
	}
    }

  if (l->l_info[ADDRIDX (DT_TLSDESC_GOT)] && lazy)
    *(ElfW(Addr)*)(D_PTR (l, l_info[ADDRIDX (DT_TLSDESC_GOT)]) + l->l_addr)
      = (ElfW(Addr)) &_dl_tlsdesc_resolve_rela;

  return lazy;
}

/* Initial entry point code for the dynamic linker.
   The C function `_dl_start' is the real entry point;
   its return value is the user program's entry point.  */
#define RTLD_START asm ("\n\
.text\n\
	.align 16\n\
.globl _start\n\
.globl _dl_start_user\n\
_start:\n\
	movq %rsp, %rdi\n\
	call _dl_start\n\
_dl_start_user:\n\
	# Save the user entry point address in %r12.\n\
	movq %rax, %r12\n\
	# See if we were run as a command with the executable file\n\
	# name as an extra leading argument.\n\
	movl _dl_skip_args(%rip), %eax\n\
	# Pop the original argument count.\n\
	popq %rdx\n\
	# Adjust the stack pointer to skip _dl_skip_args words.\n\
	leaq (%rsp,%rax,8), %rsp\n\
	# Subtract _dl_skip_args from argc.\n\
	subl %eax, %edx\n\
	# Push argc back on the stack.\n\
	pushq %rdx\n\
	# Call _dl_init (struct link_map *main_map, int argc, char **argv, char **env)\n\
	# argc -> rsi\n\
	movq %rdx, %rsi\n\
	# Save %rsp value in %r13.\n\
	movq %rsp, %r13\n\
	# And align stack for the _dl_init call. \n\
	andq $-16, %rsp\n\
	# _dl_loaded -> rdi\n\
	movq _rtld_local(%rip), %rdi\n\
	# env -> rcx\n\
	leaq 16(%r13,%rdx,8), %rcx\n\
	# argv -> rdx\n\
	leaq 8(%r13), %rdx\n\
	# Clear %rbp to mark outermost frame obviously even for constructors.\n\
	xorl %ebp, %ebp\n\
	# Call the function to run the initializers.\n\
	call _dl_init\n\
	# Pass our finalizer function to the user in %rdx, as per ELF ABI.\n\
	leaq _dl_fini(%rip), %rdx\n\
	# And make sure %rsp points to argc stored on the stack.\n\
	movq %r13, %rsp\n\
	# Jump to the user's entry point.\n\
	jmp *%r12\n\
.previous\n\
");

/* ELF_RTYPE_CLASS_PLT iff TYPE describes relocation of a PLT entry or
   TLS variable, so undefined references should not be allowed to
   define the value.
   ELF_RTYPE_CLASS_COPY iff TYPE should not be allowed to resolve to one
   of the main executable's symbols, as for a COPY reloc.
   ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA iff TYPE describes relocation may
   against protected data whose address be external due to copy relocation.
 */
#define elf_machine_type_class(type)					      \
  ((((type) == R_X86_64_JUMP_SLOT					      \
     || (type) == R_X86_64_DTPMOD64					      \
     || (type) == R_X86_64_DTPOFF64					      \
     || (type) == R_X86_64_TPOFF64					      \
     || (type) == R_X86_64_TLSDESC)					      \
    * ELF_RTYPE_CLASS_PLT)						      \
   | (((type) == R_X86_64_COPY) * ELF_RTYPE_CLASS_COPY)			      \
   | (((type) == R_X86_64_GLOB_DAT) * ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA))

/* A reloc type used for ld.so cmdline arg lookups to reject PLT entries.  */
#define ELF_MACHINE_JMP_SLOT	R_X86_64_JUMP_SLOT

/* The relative ifunc relocation.  */
// XXX This is a work-around for a broken linker.  Remove!
#define ELF_MACHINE_IRELATIVE	R_X86_64_IRELATIVE

/* The x86-64 never uses Elf64_Rel/Elf32_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1
#define ELF_MACHINE_NO_RELA 0

/* We define an initialization function.  This is called very early in
   _dl_sysdep_start.  */
#define DL_PLATFORM_INIT dl_platform_init ()

static inline void __attribute__ ((unused))
dl_platform_init (void)
{
  if (GLRO(dl_platform) != NULL && *GLRO(dl_platform) == '\0')
    /* Avoid an empty string which would disturb us.  */
    GLRO(dl_platform) = NULL;

  init_cpu_features (&GLRO(dl_x86_cpu_features));
}

static inline ElfW(Addr)
elf_machine_fixup_plt (struct link_map *map, lookup_t t,
		       const ElfW(Rela) *reloc,
		       ElfW(Addr) *reloc_addr, ElfW(Addr) value)
{
  return *reloc_addr = value;
}

/* Return the final value of a PLT relocation.  On x86-64 the
   JUMP_SLOT relocation ignores the addend.  */
static inline ElfW(Addr)
elf_machine_plt_value (struct link_map *map, const ElfW(Rela) *reloc,
		       ElfW(Addr) value)
{
  return value;
}


/* Names of the architecture-specific auditing callback functions.  */
#define ARCH_LA_PLTENTER x86_64_gnu_pltenter
#define ARCH_LA_PLTEXIT x86_64_gnu_pltexit

#endif /* !dl_machine_h */

#ifdef RESOLVE_MAP

/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

auto inline void
__attribute__ ((always_inline))
elf_machine_rela (struct link_map *map, const ElfW(Rela) *reloc,
		  const ElfW(Sym) *sym, const struct r_found_version *version,
		  void *const reloc_addr_arg, int skip_ifunc)
{
  ElfW(Addr) *const reloc_addr = reloc_addr_arg;
  //if (map)
  //	if (map->l_name)
  //		_dl_debug_printf ("map->l_name = %s\n", map->l_name);
  //_dl_debug_printf ("elf_machine_rela s --> reloc_addr = 0x%lx, *reloc_addr = 0x%lx \n", (unsigned long int) reloc_addr, (((unsigned long int) *reloc_addr)));
   void *pre_relocation_value = (void*) *reloc_addr;
  // if ((((unsigned long int) *reloc_addr) - 6) > 0x400000 && (((unsigned long int) *reloc_addr) - 6) <0x4fffff)
  // _dl_debug_printf ("*reloc_addr = 0x%lx \n", *(unsigned long int *)(((unsigned long int) *reloc_addr) - 6));
  const unsigned long int r_type = ELFW(R_TYPE) (reloc->r_info);

# if !defined RTLD_BOOTSTRAP || !defined HAVE_Z_COMBRELOC
  if (__glibc_unlikely (r_type == R_X86_64_RELATIVE))
    {
#  if !defined RTLD_BOOTSTRAP && !defined HAVE_Z_COMBRELOC
      /* This is defined in rtld.c, but nowhere in the static libc.a;
	 make the reference weak so static programs can still link.
	 This declaration cannot be done when compiling rtld.c
	 (i.e. #ifdef RTLD_BOOTSTRAP) because rtld.c contains the
	 common defn for _dl_rtld_map, which is incompatible with a
	 weak decl in the same file.  */
#   ifndef SHARED
      weak_extern (GL(dl_rtld_map));
#   endif
      if (map != &GL(dl_rtld_map)) /* Already done in rtld itself.  */
#  endif
	*reloc_addr = map->l_addr + reloc->r_addend;
    }
  else
# endif
# if !defined RTLD_BOOTSTRAP
  /* l_addr + r_addend may be > 0xffffffff and R_X86_64_RELATIVE64
     relocation updates the whole 64-bit entry.  */
  if (__glibc_unlikely (r_type == R_X86_64_RELATIVE64))
    *(Elf64_Addr *) reloc_addr = (Elf64_Addr) map->l_addr + reloc->r_addend;
  else
# endif
  if (__glibc_unlikely (r_type == R_X86_64_NONE))
    return;
  else
    {
# ifndef RTLD_BOOTSTRAP
      const ElfW(Sym) *const refsym = sym;
# endif
      struct link_map *sym_map = RESOLVE_MAP (&sym, version, r_type);
      ElfW(Addr) value = (sym == NULL ? 0
			  : (ElfW(Addr)) sym_map->l_addr + sym->st_value);
//       if(sym != NULL)
// _dl_debug_printf("ELFW(ST_TYPE) (sym->st_info) = %x, STT_GNU_IFUNC = %x\n", ELFW(ST_TYPE) (sym->st_info), STT_GNU_IFUNC);
      if (sym != NULL
	  && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC,
			       0)
	  && __builtin_expect (sym->st_shndx != SHN_UNDEF, 1)
	  && __builtin_expect (!skip_ifunc, 1))
	value = ((ElfW(Addr) (*) (void)) value) ();

      switch (r_type)
	{
# ifndef RTLD_BOOTSTRAP
#  ifdef __ILP32__
	case R_X86_64_SIZE64:
	  /* Set to symbol size plus addend.  */
	  *(Elf64_Addr *) (uintptr_t) reloc_addr
	    = (Elf64_Addr) sym->st_size + reloc->r_addend;
	  break;

	case R_X86_64_SIZE32:
#  else
	case R_X86_64_SIZE64:
#  endif
	  /* Set to symbol size plus addend.  */
	  value = sym->st_size;
# endif
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT:
	  *reloc_addr = value + reloc->r_addend;
	  break;

# ifndef RESOLVE_CONFLICT_FIND_MAP
	case R_X86_64_DTPMOD64:
#  ifdef RTLD_BOOTSTRAP
	  /* During startup the dynamic linker is always the module
	     with index 1.
	     XXX If this relocation is necessary move before RESOLVE
	     call.  */
	  *reloc_addr = 1;
#  else
	  /* Get the information from the link map returned by the
	     resolve function.  */
	  if (sym_map != NULL)
	    *reloc_addr = sym_map->l_tls_modid;
#  endif
	  break;
	case R_X86_64_DTPOFF64:
#  ifndef RTLD_BOOTSTRAP
	  /* During relocation all TLS symbols are defined and used.
	     Therefore the offset is already correct.  */
	  if (sym != NULL)
	    {
	      value = sym->st_value + reloc->r_addend;
#   ifdef __ILP32__
	      /* This relocation type computes a signed offset that is
		 usually negative.  The symbol and addend values are 32
		 bits but the GOT entry is 64 bits wide and the whole
		 64-bit entry is used as a signed quantity, so we need
		 to sign-extend the computed value to 64 bits.  */
	      *(Elf64_Sxword *) reloc_addr = (Elf64_Sxword) (Elf32_Sword) value;
#   else
	      *reloc_addr = value;
#   endif
	    }
#  endif
	  break;
	case R_X86_64_TLSDESC:
	  {
	    struct tlsdesc volatile *td =
	      (struct tlsdesc volatile *)reloc_addr;

#  ifndef RTLD_BOOTSTRAP
	    if (! sym)
	      {
		td->arg = (void*)reloc->r_addend;
		td->entry = _dl_tlsdesc_undefweak;
	      }
	    else
#  endif
	      {
#  ifndef RTLD_BOOTSTRAP
#   ifndef SHARED
		CHECK_STATIC_TLS (map, sym_map);
#   else
		if (!TRY_STATIC_TLS (map, sym_map))
		  {
		    td->arg = _dl_make_tlsdesc_dynamic
		      (sym_map, sym->st_value + reloc->r_addend);
		    td->entry = _dl_tlsdesc_dynamic;
		  }
		else
#   endif
#  endif
		  {
		    td->arg = (void*)(sym->st_value - sym_map->l_tls_offset
				      + reloc->r_addend);
		    td->entry = _dl_tlsdesc_return;
		  }
	      }
	    break;
	  }
	case R_X86_64_TPOFF64:
	  /* The offset is negative, forward from the thread pointer.  */
#  ifndef RTLD_BOOTSTRAP
	  if (sym != NULL)
#  endif
	    {
#  ifndef RTLD_BOOTSTRAP
	      CHECK_STATIC_TLS (map, sym_map);
#  endif
	      /* We know the offset of the object the symbol is contained in.
		 It is a negative value which will be added to the
		 thread pointer.  */
	      value = (sym->st_value + reloc->r_addend
		       - sym_map->l_tls_offset);
#  ifdef __ILP32__
	      /* The symbol and addend values are 32 bits but the GOT
		 entry is 64 bits wide and the whole 64-bit entry is used
		 as a signed quantity, so we need to sign-extend the
		 computed value to 64 bits.  */
	      *(Elf64_Sxword *) reloc_addr = (Elf64_Sxword) (Elf32_Sword) value;
#  else
	      *reloc_addr = value;
#  endif
	    }
	  break;
# endif

# ifndef RTLD_BOOTSTRAP
	case R_X86_64_64:
	  /* value + r_addend may be > 0xffffffff and R_X86_64_64
	     relocation updates the whole 64-bit entry.  */
	  *(Elf64_Addr *) reloc_addr = (Elf64_Addr) value + reloc->r_addend;
	  break;
#  ifndef __ILP32__
	case R_X86_64_SIZE32:
	  /* Set to symbol size plus addend.  */
	  value = sym->st_size;
#  endif
	case R_X86_64_32:
	  value += reloc->r_addend;
	  *(unsigned int *) reloc_addr = value;

	  const char *fmt;
	  if (__glibc_unlikely (value > UINT_MAX))
	    {
	      const char *strtab;

	      fmt = "\
%s: Symbol `%s' causes overflow in R_X86_64_32 relocation\n";
#  ifndef RESOLVE_CONFLICT_FIND_MAP
	    print_err:
#  endif
	      strtab = (const char *) D_PTR (map, l_info[DT_STRTAB]);

	      _dl_error_printf (fmt, RTLD_PROGNAME, strtab + refsym->st_name);
	    }
	  break;
#  ifndef RESOLVE_CONFLICT_FIND_MAP
	  /* Not needed for dl-conflict.c.  */
	case R_X86_64_PC32:
	  value += reloc->r_addend - (ElfW(Addr)) reloc_addr;
	  *(unsigned int *) reloc_addr = value;
	  if (__glibc_unlikely (value != (int) value))
	    {
	      fmt = "\
%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation\n";
	      goto print_err;
	    }
	  break;
	case R_X86_64_COPY:
	  if (sym == NULL)
	    /* This can happen in trace mode if an object could not be
	       found.  */
	    break;
	  memcpy (reloc_addr_arg, (void *) value,
		  MIN (sym->st_size, refsym->st_size));
	  if (__builtin_expect (sym->st_size > refsym->st_size, 0)
	      || (__builtin_expect (sym->st_size < refsym->st_size, 0)
		  && GLRO(dl_verbose)))
	    {
	      fmt = "\
%s: Symbol `%s' has different size in shared object, consider re-linking\n";
	      goto print_err;
	    }
	  break;
#  endif
	case R_X86_64_IRELATIVE:
	  value = map->l_addr + reloc->r_addend;
	  value = ((ElfW(Addr) (*) (void)) value) ();
	  *reloc_addr = value;
	  break;
	default:
	  _dl_reloc_bad_type (map, r_type, 0);
	  break;
# endif
	}
    }
  //_dl_debug_printf ("elf_machine_rela e --> reloc_addr = 0x%lx, *reloc_addr = 0x%lx \n", (unsigned long int)reloc_addr, (((unsigned long int) *reloc_addr)));
  /* _CDI_: Modify the plt to a direct call to the actural relocated address. */

  if ((unsigned long int)pre_relocation_value > 0x400000) {
      /*Check if the library is cdi compliant library.*/
      CLB *clb = _cdi_clb_from_soname(map->l_name);
      if (!clb && strcmp(map->l_name,"")){
          return;
      }
      //_dl_debug_printf ("**** CDI lib relocation :\n");
      unsigned char *plt = 0;
      /*.plt.got since .got comes after .plt.got negative offset implies .plt.got */
      if ((unsigned long int)pre_relocation_value >  0xf000000000000000){
          //_dl_debug_printf ("****fixing a slow_plt ****:\n");
          //_dl_debug_printf ("pre_relocation_value = 0x%lx reloc_addr = 0x%lx\n", (unsigned long int)pre_relocation_value, (unsigned long int)reloc_addr);
          //_dl_debug_printf ("relocated_to = %lx \n", (unsigned long int) *reloc_addr);
          unsigned char *slow_plt = (unsigned char*)((unsigned long int)pre_relocation_value + (unsigned long int)reloc_addr);
          unsigned char *target = (unsigned char*) *reloc_addr;
          if (!target) {
              return;
          }
          //_dl_debug_printf_c("HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIT\n");
          //
          //_dl_debug_printf_c("bytes: %u, %u, %u, %u\n", target[0], target[1], target[6], target[11]);

          /* check for the format of a PLT */
          if (target[0] == 0xff && target[1] == 0x25
                  && target[6] == 0x68 && target[11] == 0xe9) {
              /* we're probably looking at a PLT. Let's make sure by checking 
               * the format of the first PLT in the code object */
              unsigned char *first_plt = *(ElfW(Sword)*)(target + 12) + (target + 16); 
              if (first_plt[0] == 0xff && first_plt[1] == 0x35
                      && first_plt[6] == 0xff && first_plt[7] == 0x25
                      && first_plt[12] == 0x0f && first_plt[13] == 0x1f
                      && first_plt[14] == 0x40 && first_plt[15] == 0x00) {
                  /* we're looking at a PLT entry */
                  ElfW(Word) got_reloff = *(ElfW(Word)*)(target + 2);
                  ElfW(Addr) *got_entry = (ElfW(Addr) *)(target + 6 + got_reloff);


                  if (*got_entry == (uintptr_t)target + 6) {
                      /* the GOT entry hasn't been relocated nor has it been
                       * chained to slow plts. Start the chain */

                      *got_entry = (uintptr_t)slow_plt;
                      //_cdi_print_plt_bytes(slow_plt, "start chain before");
                      _cdi_write_direct_plt(slow_plt, &target, 0);
                      //_cdi_print_plt_bytes(slow_plt, "start chain after");
                  }
                  else if (*(unsigned char *)(*got_entry + 13) == 0x0f 
                          && *(unsigned char *)(*got_entry + 14) == 0x0b) {
                      /* the got entry points to a slow plt. Add ourselves to
                       * the chain */

                      //_cdi_print_plt_bytes(slow_plt, "chain before");
                      _cdi_write_direct_plt(slow_plt, got_entry, 0);
                      //_cdi_print_plt_bytes(slow_plt, "chain after");
                      *got_entry = (uintptr_t)slow_plt;
                  }
                  else {
                      unsigned char force_jump = 0;
                      if (*(unsigned char*)(slow_plt + 15) == 0xcc) {
                          force_jump = 1;
                      }
                      /* the got entry has already been relocated to point to 
                       * the function this chain of plts is associated with
                       *
                       * just take the address from the got and go there
                       */
                      _cdi_write_direct_plt(slow_plt, (void*)*got_entry, !force_jump);
                      //_dl_debug_printf_c("FATAL ERROR: how did we get here?\n");
                  }
                  return;
              }
          }
          /* check for the format of a CDI direct call plt */
          else if (target[0] == 0x49 && target[1] == 0xbb 
                  && target[10] == 0x41 && target[11] == 0xff
                  && target[12] == 0xd3 && target[13] == 0x0f) {
              /* the GOT has been relocated to point to a fixed up PLT */
              /* snatch the function's address from the CDI PLT */
              //_cdi_print_plt_bytes(slow_plt, "cdi direct before");
              _cdi_write_direct_plt(slow_plt, target + 2, 1);
              //_cdi_print_plt_bytes(slow_plt, "cdi direct after");
          }
          else {
              /* we're pointing directly to the function */

              /* we're not sure why force_jump is needed here, but it fixes
               * the problem. Currently this is the only place in which
               * force_jump is needed, but the other modifications will be left
               * because those locations are more logically the place where changes
               * should be made to support non cdi calls in a cdi code object
               */
              unsigned char force_jump = 0;
              if (*(unsigned char*)(slow_plt + 15) == 0xcc) {
                  force_jump = 1;
              }
              //_cdi_print_plt_bytes(slow_plt, "direct before");
              _cdi_write_direct_plt(slow_plt, &target, !force_jump);
              //_cdi_print_plt_bytes(slow_plt, "direct after");
          }

          return;
      }

      /* check if it points to chain of slow plts*/
      if (*((unsigned char*)(pre_relocation_value + 13)) == 0x0f
              && *((unsigned char*)(pre_relocation_value + 14)) == 0x0b) {
          //_dl_debug_printf_c("-- fixing chain of slow plts: *pre_1 = %lx\n", *((unsigned long int*)pre_relocation_value + 2));

          /* check for chain of fast plts*/
          unsigned long int relocated_to = (unsigned long int) *reloc_addr;
          ElfW(Addr) plt_chain = *((ElfW(Addr) *)((unsigned char *)pre_relocation_value + 2));

          /* use jump if the last byte of the PLT is 0xcc. This is used to whitelist
           * functions like __cxa_finalize which are not CDI but use the fast_plt
           * mechanism */
          unsigned char force_jump = 0;
          if (*(unsigned char*)(pre_relocation_value + 15) == 0xcc) {
              force_jump = 1;
          }

          //_cdi_print_plt_bytes(pre_relocation_value, "resolve first before");
          _cdi_write_direct_plt(pre_relocation_value, &relocated_to, !force_jump);
          //_cdi_print_plt_bytes(pre_relocation_value, "resolve first after");
          //_dl_debug_printf_c ("c = %lx, *c1 = %lx \n", (unsigned long int)plt_chain, *(unsigned long int*)plt_chain );
          /*process all the fast plts in the chain*/
          while(*((unsigned char*)(plt_chain + 13)) == 0x0f && 
                  *((unsigned char*)(plt_chain + 14)) == 0x0b) {
              force_jump = 0;
              if (*(unsigned char*)(plt_chain + 15) == 0xcc) {
                  force_jump = 1;
              }
              ElfW(Addr) tmp = *((ElfW(Addr) *)((unsigned char *)plt_chain + 2));
              //_cdi_print_plt_bytes((void*)plt_chain, "resolve before");
              _cdi_write_direct_plt((void *)plt_chain, &relocated_to, !force_jump);
              //_cdi_print_plt_bytes((void*)plt_chain, "resolve after");
              plt_chain = tmp;
              _dl_debug_printf_c ("c = %lx, *c = %lx \n", (unsigned long int)plt_chain, *(unsigned long int*)plt_chain );
          }

          /*finally update the plt itself*/
          //_cdi_print_plt_bytes((void*)plt_chain, "resolve last before");
          _cdi_write_direct_plt((void *)plt_chain, &relocated_to, !force_jump);
          //_cdi_print_plt_bytes((void*)plt_chain, "resolve last after");
      }
      else {
          /*It points the second instruction in it's own plt*/
          plt = (unsigned char*)(pre_relocation_value - 6);
          if((unsigned long int)reloc_addr > 0x700000000000 && strcmp(map->l_name,"")){		
              plt += map->l_addr;
          }

          unsigned long int relocated_to = (unsigned long int) *reloc_addr;
          if (!relocated_to) {
              return;
          }

          if (!_cdi_addr_is_in_cdi_sl(relocated_to)) {
              return;
          }

          //_dl_debug_printf ("***doing fixup\n");
          //_cdi_print_plt_bytes(plt, "overwrite before");
          _cdi_write_direct_plt(plt, &relocated_to, 1);
          //_cdi_print_plt_bytes(plt, "overwrite after");
      }  		
  }
}

auto inline void
__attribute ((always_inline))
elf_machine_rela_relative (ElfW(Addr) l_addr, const ElfW(Rela) *reloc,
			   void *const reloc_addr_arg)
{
	//_dl_debug_printf ("***elf_machine_rela_relative\n");
 
  ElfW(Addr) *const reloc_addr = reloc_addr_arg;
  //_dl_debug_printf ("--> reloc_addr = %lx, *reloc_addr = 0x%lx l_addr = %lx, reloc->r_addend = %lx\n", (unsigned long int) reloc_addr, (((unsigned long int) *reloc_addr)), (unsigned long int)l_addr, (unsigned long int)reloc->r_addend);
#if !defined RTLD_BOOTSTRAP
  /* l_addr + r_addend may be > 0xffffffff and R_X86_64_RELATIVE64
     relocation updates the whole 64-bit entry.  */
  if (__glibc_unlikely (ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE64))
    *(Elf64_Addr *) reloc_addr = (Elf64_Addr) l_addr + reloc->r_addend;
  else
#endif
    {
      assert (ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE);
      *reloc_addr = l_addr + reloc->r_addend;
    }
}

auto inline void
__attribute ((always_inline))
elf_machine_lazy_rel (struct link_map *map,
		      ElfW(Addr) l_addr, const ElfW(Rela) *reloc,
		      int skip_ifunc)
{
	//_dl_debug_printf ("***elf_machine_lazy_rel\n");
  ElfW(Addr) *const reloc_addr = (void *) (l_addr + reloc->r_offset);
  const unsigned long int r_type = ELFW(R_TYPE) (reloc->r_info);

  /* Check for unexpected PLT reloc type.  */
  if (__glibc_likely (r_type == R_X86_64_JUMP_SLOT))
    {
      if (__builtin_expect (map->l_mach.plt, 0) == 0)
	*reloc_addr += l_addr;
      else
	*reloc_addr =
	  map->l_mach.plt
	  + (((ElfW(Addr)) reloc_addr) - map->l_mach.gotplt) * 2;
    }
  else if (__glibc_likely (r_type == R_X86_64_TLSDESC))
    {
      struct tlsdesc volatile * __attribute__((__unused__)) td =
	(struct tlsdesc volatile *)reloc_addr;

      td->arg = (void*)reloc;
      td->entry = (void*)(D_PTR (map, l_info[ADDRIDX (DT_TLSDESC_PLT)])
			  + map->l_addr);
    }
  else if (__glibc_unlikely (r_type == R_X86_64_IRELATIVE))
    {
      ElfW(Addr) value = map->l_addr + reloc->r_addend;
      if (__glibc_likely (!skip_ifunc))
	value = ((ElfW(Addr) (*) (void)) value) ();
      *reloc_addr = value;
    }
  else
    _dl_reloc_bad_type (map, r_type, 1);
}

#endif /* RESOLVE_MAP */
