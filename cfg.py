import types

class ControlFlowGraph:
    def __init__(self):
        # don't touch this attribute
        self._funct_edges = dict()

    def add_funct(self, funct):
        self._funct_edges[funct.name] = funct

    def funct(self, funct_name):
        return self._funct_edges[funct_name]

class Function:
    def __init__(self, name, sites, return_set):
        assert name is types.StringType
        assert return_set is TupleType

        # all functions that can be returned to in the format:
        # (function_label, num_times_function_calls_this_one)
        self.return_set = return_set
        self.name = name
        self.sites = sites

class Site:
    def __init__(self, line_num, targets):
        assert line_num is types.IntType
        assert targets is types.ListType

        self.line_num = line_num
        self.targets = targets
