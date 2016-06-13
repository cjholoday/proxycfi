import types

class ControlFlowGraph:
    def __init__(self):
        # don't touch this attribute
        self._funct_vertices = dict()

    def add_funct(self, funct):
        self._funct_vertices[funct.name] = funct

    def funct(self, funct_name):
        return self._funct_vertices[funct_name]

    def __iter__(self):
        return iter(ControlFlowGraphIterator(self))

class ControlFlowGraphIterator:
    def __init__(self, cfg):
        self.cfg_iter = cfg._funct_vertices.iteritems()

    def __iter__(self):
        return self

    def next(self):
        return self.cfg_iter.next()[1]

class Function:
    def __init__(self, name, sites, return_dict):
        assert type(name) is types.StringType
        self.return_dict = return_dict
        self.name = name
        self.sites = sites

class Site:
    CALL_SITE = 0
    RETURN_SITE = 1
    INDIR_JMP_SITE = 2

    def __init__(self, line_num, targets, type_of_site):
        assert type(line_num) is types.IntType
        assert type(type_of_site) is types.IntType
        assert (type_of_site == Site.CALL_SITE or 
                type_of_site == Site.RETURN_SITE or
                type_of_site == Site.INDIR_JMP_SITE)
        self.line_num = line_num
        self.targets = targets
        self.site_type = type_of_site
