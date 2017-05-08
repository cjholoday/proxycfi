$(common-objpfx)string/rtld-memcpy-sse2-unaligned.os: \
 ../sysdeps/x86_64/multiarch/memcpy-sse2-unaligned.S \
 ../include/stdc-predef.h \
 $(common-objpfx)libc-modules.h \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/generic/symbol-hacks.h

../include/stdc-predef.h:

$(common-objpfx)libc-modules.h:

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/generic/symbol-hacks.h:
