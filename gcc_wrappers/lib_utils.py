import __init__

import subprocess
import os
import re
import sys

import spec
import fake_types
from common.eprint import eprint
from error import fatal_error

def ar_extract_req_objs(verbose_output, archives):
    """Extracts required objs from archives and return ([fake objs], [ar_fixups])
    
    Required objects are extracted into ./.cdi with the following format:
        libname.a__obj_name.fake.o
    """

    # {archive path -> objs paths needed}
    objs_needed = dict()
    
    # matching strings in the form '(libname.a)obj_name.o'
    # characters are allowed after '.o' since some build systems do it
    matcher = re.compile(r'^\([^()\s]+\.a\)[^()\s]+\.o[^()\s]*$')

    # maps {libname from verbose output -> full archive path}
    ar_full_path = dict()
    for archive in archives:
        ar_full_path['.cdi/' + os.path.basename(archive.path)] = archive.path

    for line in verbose_output.split('\n'):
        if matcher.match(line):
            end_paren_idx = line.find(')')
            ar_rel_path = line[1:end_paren_idx]
            if ar_rel_path.startswith('.cdi/'):
                ar_path = ar_full_path[ar_rel_path]
            else:
                ar_path = os.path.realpath(line[1:end_paren_idx])

            obj_fname = line[end_paren_idx + 1:]
            try:
                objs_needed[ar_path].append(obj_fname)
            except KeyError:
                objs_needed[ar_path] = [obj_fname]

    # for code visibility, print all objects that are needed from archives
    for ar_path in objs_needed.keys():
        print ':::: {} - {}'.format(ar_path, ' '.join(objs_needed[ar_path]))

    ar_fixups = []
    fake_objs = []
    ar_handled = dict() # maps { ar_realpath -> was_already_handled}
    for archive in archives:
        # ignore duplicate archives
        if ar_handled.get(os.path.realpath(archive.path)):
            ar_fixups.append(spec.LinkerSpec.Fixup('ar', archive.fixup_idx, ''))
            continue
        else:
            ar_handled[os.path.realpath(archive.path)] = True

        ar_fixup = spec.LinkerSpec.Fixup('ar', archive.fixup_idx, [])

        if archive.is_thin() and archive.path in objs_needed.keys():
            for fname in objs_needed[archive.path]:
                corrected_fname = chop_suffix(fname, '.') + '.fake.o'
                subprocess.check_call(['cp', chop_suffix(archive.path, '/')
                    + '/' + fname, corrected_fname])
                fake_objs.append(fake_types.FakeObjectFile(corrected_fname))
        elif archive.path in objs_needed.keys():
            obj_fnames = objs_needed[archive.path]

            ar_effective_path = ''
            if archive.path.startswith('/'):
                ar_effective_path = archive.path
            else:
                ar_effective_path = '../' + archive.path

            os.chdir('.cdi')
            try:
                subprocess.check_call(['ar', 'x', ar_effective_path] + obj_fnames)
            except subprocess.CalledProcessError:
                fatal_error("cannot extract '{}' from non-thin archive '{}'"
                        .format( "' '".join(obj_fnames), archive.path))

            os.chdir('..')
            for fname in obj_fnames:
                qualified_fname = '{}__{}'.format(os.path.basename(archive.path), fname)
                if not qualified_fname.endswith('.fake.o'):
                    qualified_fname = chop_suffix(qualified_fname) + '.fake.o'
                subprocess.check_call(['mv', '.cdi/' + fname, '.cdi/' + qualified_fname])
                fake_objs.append(fake_types.FakeObjectFile('.cdi/' + qualified_fname))

                # By link time, the fake object will be assembled into a '.o'
                # file. We need to fixup with the new object file
                ar_fixup.replacement.append('.cdi/' + qualified_fname.replace('.fake.o', '.cdi.o'))
        ar_fixups.append(ar_fixup)
    return fake_objs, ar_fixups

def sl_cdi_fixups(lspec, binary_path):
    """Returns a list of fixups for creating CDI shared libraries"""

    sl_cdi_paths = dict()
    for sl_path, garbage in sl_trace_bin(binary_path):
        sl_realpath = os.path.realpath(sl_path)

        # Pending on CDI shared libraries being implemented:
        #
        # Full CDI shared libraries are stored in cdi/lib
        # candidate = '/usr/local/cdi/lib/' + os.path.basename(sl_realpath)
        # if os.path.isfile(candidate):
        #     sl_cdi_paths.append(candidate)
        #     continue

        # Unsafe, unstripped non-CDI shared libraries are stored in cdi/ulib
        candidate = '/usr/local/cdi/ulib/' + os.path.basename(sl_realpath)
        if os.path.isfile(candidate):
            eprint("cdi-ld: warning: compiling against non-CDI shared library"
                    " '{}'".format(candidate))
            sl_cdi_paths[sl_realpath] = candidate
            continue

        if 'libcrypto' in sl_realpath:
            sys.exit(1)
        symbol_ref = sl_symbol_ref(sl_realpath)
        if symbol_ref == sl_path:
            eprint("cdi-ld: warning: compiling against non-CDI shared library"
                    " '{}'".format(sl_path))
        else:
            eprint("cdi-ld: warning: compiling against non-CDI shared library"
                    " '{}' with symbol reference '{}'".format(sl_path, symbol_ref))

    sl_fixups = []
    for idx, sl_path in enumerate(lspec.sl_paths):
        sl_realpath = os.path.realpath(sl_path)
        if sl_realpath in sl_cdi_paths:
            sl_fixups.append(spec.LinkerSpec.Fixup('sl', idx, sl_cdi_paths[sl_realpath]))

    sl_fixups.append(get_cdi_runtime_search_path_fixup(lspec))
    return sl_fixups

def has_symbol_table(elf_path):
    """Returns true if the elf executable at elf_path has a ".symtab" section"""

    section_info = subprocess.check_output(['readelf', '-S', elf_path])
    symtab_matcher = re.compile(r'\s*\[[\s0-9]*\] .symtab\s*SYMTAB')
    for line in section_info.splitlines():
        if symtab_matcher.match(line):
            return True
    else:
        return False

def sl_linker_name(shared_lib_path):
    """ /path/to/libshared_lib.so.1.0.0 -> libshared_lib.so """
    trimmed_name = os.path.basename(shared_lib_path)
    while not trimmed_name.endswith('.so'):
        trimmed_name = trimmed_name[:-1]
    return trimmed_name
    
def sl_symbol_ref(sl_path):
    sl_realpath = os.path.realpath(sl_path)
    if has_symbol_table(sl_path):
        return sl_path

    candidate_path = '/usr/local/cdi/ulib/' + os.path.basename(sl_realpath)
    if os.path.isfile(candidate_path) and has_symbol_table(candidate_path):
        return candidate_path

    candidate_path = '/usr/local/cdi/ulib/debug/' + os.path.basename(sl_realpath)
    if os.path.isfile(candidate_path) and has_symbol_table(candidate_path):
        return candidate_path

    sl_trimmed_realpath = os.path.basename(sl_realpath)
    for root, dirs, files in os.walk('/usr/lib/debug', topdown=True):
        if sl_trimmed_realpath in files:
            return os.path.join(root, sl_trimmed_realpath)
    else:
        fatal_error("cannot find unstripped version of shared library '{}'"
                ". Either compile it with CDI or install an unstripped"
                " version".format(sl_realpath))

def get_script_dir():
    return os.path.dirname(os.path.realpath(__file__))

find_fptrs_script = get_script_dir() + '/find_fptrs.py'
def sl_get_fptr_addrs(binary_path, symbol_ref, lib_load_addr):
    cached_analysis_path = (get_script_dir() 
            + '/../cdi-gcc/cached_fptr_analysis/' 
            + os.path.basename(os.path.realpath(binary_path)))

    fptr_analysis = []
    # either use cached analysis or create a new analysis and cache it
    if (os.path.isfile(cached_analysis_path)
            and os.path.getmtime(cached_analysis_path) >= os.path.getmtime(binary_path)
            and os.path.getmtime(cached_analysis_path) >= os.path.getmtime(symbol_ref)):
        with open(cached_analysis_path, 'r') as cached_analysis:
            fptr_analysis = cached_analysis.readlines()
    else:
        try:
            print 'generating and caching fptr analysis for {}'.format(binary_path)
            sys.stdout.flush()

            fptr_analysis = subprocess.check_output([find_fptrs_script, binary_path,
                symbol_ref]).strip()
        except subprocess.CalledProcessError as err:
            fatal_error("couldn't analyze '{}' for fptrs despite "
                    "having an associated symbol table (.symtab) in file '{}'"
                    .format(binary_path, symbol_ref))
        try:
            with open(cached_analysis_path, 'w') as cached_analysis:
                cached_analysis.write(fptr_analysis)
        except IOError:
            eprint("cdi-ld: warning: failed to cache fptr analysis for "
                    "shared library '{}'".format(os.path.basename(sl_realpath)))
        fptr_analysis = fptr_analysis.splitlines()

    fptr_addrs = []
    for line in fptr_analysis:
        fptr_lib_offset = int(line.split()[0], 16)
        fptr_addr = hex(lib_load_addr + fptr_lib_offset)
        fptr_addrs.append(fptr_addr)

    return fptr_addrs

def sl_trace_bin(execname):
    """Get pairs of (shared lib path, load address). 

    There must be an ELF executable CDI or otherwise already generated. Since
    a non-CDI executable is generated for archive analysis, this is always the
    case
    """
    lib_addr_pairs = []
    traced_output = subprocess.check_output(['./' + execname], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    for line in traced_output.splitlines():
        # format of trace output: [symlink path] => [actual elf path] ([load addr])
        symlink = line.split()[0]
        path = ''
        if len(line.split()) == 2:
            # in this case the format is [actual elf path] ([load addr])
            path = symlink
        else:
            path = line.split()[2]

        if symlink.startswith('linux-vdso.so'):
            # linux-vdso is injected into each process by the kernel, so we 
            # must ignore it. Admittedly, if a user names their shared library
            # linux-vdso.so then it won't be handled by cdi-ld.py. However, 
            # they really do deserve to get burned for their naming abuse
            continue
        addr = int(line.split()[-1].lstrip('(').rstrip(')'), 16)
        lib_addr_pairs.append((path, addr))
    return lib_addr_pairs

def sl_aslr_is_enabled(binary_path):
    traced_output1 = subprocess.check_output(['./' + binary_path], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    traced_output2 = subprocess.check_output(['./' + binary_path], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    return  traced_output1 != traced_output2

def sl_chop_versioning(sl_path):
    while get_suffix(sl_path)[1:].isdigit():
        sl_path = chop_suffix(sl_path)
    return sl_path

def chop_suffix(string, cutoff = ''):
    if cutoff == '':
        return string[:string.rfind('.')]
    return string[:string.rfind(cutoff)]

def get_suffix(string, cutoff = ''):
    if cutoff == '':
        return string[string.rfind('.'):]
    return string[string.rfind(cutoff):]

def get_cdi_runtime_search_path_fixup(lspec):
    """Ensure the cdi libraries can be found at runtime
    
    This is accomplished by adding /usr/local/cdi/lib and /usr/local/cdi/ulib
    to the runtime path list at the start of the spec
    """

    replacement = [lspec.entry_lists[lspec.entry_types[0]][0], 
            '-rpath=/usr/local/cdi/lib', '-rpath=/usr/local/cdi/ulib']
    return spec.LinkerSpec.Fixup(lspec.entry_types[0], 0, replacement)

def st_vaddr(symbol, elf):
    """Use symbol table to get the virtual address of 'symbol'"""

    # Shared libraries don't need to have a symbol table
    # Find the associated file that has it
    elf = sl_symbol_ref(elf)

    p_readelf = subprocess.Popen(['readelf', '-s', elf], stdout=subprocess.PIPE)
    p_grep = subprocess.Popen(['grep', ' {}$'.format(symbol)], stdin=p_readelf.stdout,
            stdout=subprocess.PIPE)
    p_readelf.stdout.close()
    symbol_entry = p_grep.communicate()[0]
    if symbol_entry == '':
        raise KeyError("symbol '{}' not found in symbol table of '{}'".format(symbol, elf))
    return symbol_entry.split()[1]


def get_restore_rt_vaddrs(lspec):
    """Get the virtual addresses of __restore_rt, to which signal handlers return
    
    Requires that lspec.target exists and accurately reflects the load addresses
    for the associated shared libraries
    """

    vaddrs = []
    for sl_path, lib_load_addr in sl_trace_bin(lspec.target):
        try:
            vaddrs.append(hex(int(st_vaddr('__restore_rt', sl_path), 16) + lib_load_addr))
        except KeyError:
            pass # not all libraries will have '__restore_rt'

    return vaddrs

def get_vaddr(symbol, execname):
    """Get virtual address of symbol from gdb"""
    gdb_process = subprocess.Popen(['gdb', execname], stderr=subprocess.PIPE, 
            stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    gdb_process.stdin.write('b main\nrun\ninfo addr {}\nq'.format(symbol))
    vaddr = gdb_process.communicate()[0].splitlines()[-2].split()[5]

    gdb_process.stdin.close()
    return vaddr

