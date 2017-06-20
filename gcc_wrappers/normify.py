import spec
import subprocess
import os

def ar_normify(archives):
    """Creates non-CDI archives and returns a list of fixups
    
    Deletes and modifies ./.cdi
    """

    ar_fixups = []

    # stale files in .cdi can cause trouble
    subprocess.check_call(['rm', '-rf', '.cdi'])
    subprocess.check_call(['mkdir', '.cdi'])

    os.chdir('.cdi')
    for archive in archives:
        ar_fixups.append(spec.LinkerSpec.Fixup('ar', archive.fixup_idx, 
            '.cdi/' + os.path.basename(archive.path)))

        ar_effective_path = ''
        if archive.path.startswith('/'):
            ar_effective_path = archive.path
        else:
            ar_effective_path = '../' + archive.path

        lines = subprocess.check_output(['ar', 'xv', ar_effective_path]).strip().split('\n')
        obj_fnames = map(lambda x: x[len('x - '):], lines)
        for obj_fname in obj_fnames:
            with open(obj_fname, 'r') as fake_obj:
                elf_signature = '\x7FELF'
                is_elf = fake_obj.read(4) == elf_signature
            if is_elf:
                continue # already real object file
            else:
                correct_obj_fname = chop_suffix(obj_fname, '.') + '.fake.o'
                subprocess.check_call(['mv', obj_fname, correct_obj_fname])
                subprocess.check_call(['as', correct_obj_fname, '-o', obj_fname])


        # TODO handle case where two archives have diff path but same names
        assert os.path.basename(archive.path) not in archives
        subprocess.check_call(['ar', 'rc', os.path.basename(archive.path)] + obj_fnames)
    os.chdir('..')
    return ar_fixups

def fake_objs_normify(fake_objs):
    """Assembles fake objects into non-CDI objects. Returns a list of fixups"""

    fixups = []
    for i, fake_obj in enumerate(fake_objs):
        target = fake_obj.path.replace('.fake.o', '.o')
        subprocess.call(['as', fake_obj.path, '-o', target] + fake_obj.as_spec_no_io)
        fixups.append(spec.LinkerSpec.Fixup('obj', fake_obj.fixup_idx, target))
    return fixups

def chop_suffix(string, cutoff = ''):
    if cutoff == '':
        return string[:string.rfind('.')]
    return string[:string.rfind(cutoff)]
