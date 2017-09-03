import csv
import collections
import pickle
#----------------------------------------
#  Running the sequences of similar jobs
#----------------------------------------

#----------------------------------------
#  loading the data from .CSV
#----------------------------------------
class CSV_Iterable:
    def __init__(self, reader):
        header = reader.next()
        for i in range(len(header)):
            header[i] = header[i].strip()
        self.csv_data = collections.namedtuple('csv_data_from_file', header)
        self.reader = reader

    def __iter__(self):
        return self

    def next(self): # Python 3: def __next__(self)
        row = self.reader.next()
        for i in range(len(row)):
            row[i] = row[i].strip()
        new_data = self.csv_data(*row)
        return new_data

def load_csv_data(ifn, preload = False):
    ifh = open(ifn, "rb")
    reader = csv.reader(ifh, quotechar='"', delimiter=',', quoting=csv.QUOTE_ALL, skipinitialspace=True, strict=True)
    iterable = CSV_Iterable(reader)
    if preload == False:
        return iterable
    else:
        data = []
        for i in iterable:
            data.append(i)
        return data

def save_obj(obj, name ):
    with open('obj/'+ name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name ):
    with open('obj/' + name + '.pkl', 'rb') as f:
        return pickle.load(f)