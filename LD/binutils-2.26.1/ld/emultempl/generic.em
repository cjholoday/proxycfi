# This shell script emits a C file. -*- C -*-
# It does some substitutions.
fragment <<EOF
/* This file is is generated by a shell script.  DO NOT EDIT! */

/* emulate the original gld for the given ${EMULATION_NAME}
   Copyright (C) 1991-2015 Free Software Foundation, Inc.
   Written by Steve Chamberlain steve@cygnus.com

   This file is part of the GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#define TARGET_IS_${EMULATION_NAME}

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"

#include "ld.h"
#include "ldmain.h"
#include "ldmisc.h"

#include "ldexp.h"
#include "ldlang.h"
#include "ldfile.h"
#include "ldemul.h"

EOF

# Import any needed special functions and/or overrides.
#
if test -n "$EXTRA_EM_FILE" ; then
  source_em ${srcdir}/emultempl/${EXTRA_EM_FILE}.em
fi

if test x"$LDEMUL_BEFORE_PARSE" != xgld"$EMULATION_NAME"_before_parse; then
fragment <<EOF

static void
gld${EMULATION_NAME}_before_parse (void)
{
#ifndef TARGET_			/* I.e., if not generic.  */
  ldfile_set_output_arch ("`echo ${ARCH}`", bfd_arch_unknown);
#endif /* not TARGET_ */
EOF
  # The MSP430 port *needs* linker relaxtion in order to cope with large
  # functions where conditional branches do not fit into a +/- 1024 byte range.
  case ${target} in
    msp430-*-* )
fragment <<EOF
  if (!bfd_link_relocatable (&link_info))
    TARGET_ENABLE_RELAXATION;
EOF
    ;;
  esac
fragment <<EOF
}

EOF
fi

if test x"$LDEMUL_GET_SCRIPT" != xgld"$EMULATION_NAME"_get_script; then
fragment <<EOF

static char *
gld${EMULATION_NAME}_get_script (int *isfile)
EOF

if test x"$COMPILE_IN" = xyes
then
# Scripts compiled in.

# sed commands to quote an ld script as a C string.
sc="-f stringify.sed"

fragment <<EOF
{
  *isfile = 0;

  if (bfd_link_relocatable (&link_info) && config.build_constructors)
    return
EOF
sed $sc ldscripts/${EMULATION_NAME}.xu                 >> e${EMULATION_NAME}.c
echo '  ; else if (bfd_link_relocatable (&link_info)) return' >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xr                 >> e${EMULATION_NAME}.c
echo '  ; else if (!config.text_read_only) return'     >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xbn                >> e${EMULATION_NAME}.c
echo '  ; else if (!config.magic_demand_paged) return' >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xn                 >> e${EMULATION_NAME}.c
echo '  ; else return'                                 >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.x                  >> e${EMULATION_NAME}.c
echo '; }'                                             >> e${EMULATION_NAME}.c

else
# Scripts read from the filesystem.

fragment <<EOF
{
  *isfile = 1;

  if (bfd_link_relocatable (&link_info) && config.build_constructors)
    return "ldscripts/${EMULATION_NAME}.xu";
  else if (bfd_link_relocatable (&link_info))
    return "ldscripts/${EMULATION_NAME}.xr";
  else if (!config.text_read_only)
    return "ldscripts/${EMULATION_NAME}.xbn";
  else if (!config.magic_demand_paged)
    return "ldscripts/${EMULATION_NAME}.xn";
  else
    return "ldscripts/${EMULATION_NAME}.x";
}
EOF
fi
fi

fragment <<EOF

struct ld_emulation_xfer_struct ld_${EMULATION_NAME}_emulation =
{
  ${LDEMUL_BEFORE_PARSE-gld${EMULATION_NAME}_before_parse},
  ${LDEMUL_SYSLIB-syslib_default},
  ${LDEMUL_HLL-hll_default},
  ${LDEMUL_AFTER_PARSE-after_parse_default},
  ${LDEMUL_AFTER_OPEN-after_open_default},
  ${LDEMUL_AFTER_ALLOCATION-after_allocation_default},
  ${LDEMUL_SET_OUTPUT_ARCH-set_output_arch_default},
  ${LDEMUL_CHOOSE_TARGET-ldemul_default_target},
  ${LDEMUL_BEFORE_ALLOCATION-before_allocation_default},
  ${LDEMUL_GET_SCRIPT-gld${EMULATION_NAME}_get_script},
  "${EMULATION_NAME}",
  "${OUTPUT_FORMAT}",
  ${LDEMUL_FINISH-finish_default},
  ${LDEMUL_CREATE_OUTPUT_SECTION_STATEMENTS-NULL},
  ${LDEMUL_OPEN_DYNAMIC_ARCHIVE-NULL},
  ${LDEMUL_PLACE_ORPHAN-NULL},
  ${LDEMUL_SET_SYMBOLS-NULL},
  ${LDEMUL_PARSE_ARGS-NULL},
  ${LDEMUL_ADD_OPTIONS-NULL},
  ${LDEMUL_HANDLE_OPTION-NULL},
  ${LDEMUL_UNRECOGNIZED_FILE-NULL},
  ${LDEMUL_LIST_OPTIONS-NULL},
  ${LDEMUL_RECOGNIZED_FILE-NULL},
  ${LDEMUL_FIND_POTENTIAL_LIBRARIES-NULL},
  ${LDEMUL_NEW_VERS_PATTERN-NULL},
  ${LDEMUL_EXTRA_MAP_FILE_TEXT-NULL}
};
EOF
