import csv


class Connection:
    attrs = ['duration','protocol_type', 'service','flag','src_bytes','dst_bytes','land',
             'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised','root_shell',
             'su_attempted','num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds',
             'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate',
             'srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
             'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
             'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
             'dst_host_srv_rerror_rate', 'label']

    def __init__(self, row):
        for idx, val in enumerate(row):
            # 1 -> 3 str columns, last is str label
            if ( (1 <= idx and idx <= 3) or  idx == 41):
                setattr(self, Connection.attrs[idx], val)
            # 24 -> 30 float columns
            elif (24 <= idx and idx <= 30):
                setattr(self, Connection.attrs[idx], float(val))
            # 33 -> 41 float columns
            elif (33 <= idx and idx <= 41):
                setattr(self, Connection.attrs[idx], float(val))
            #rest is int
            else:
                setattr(self, Connection.attrs[idx], int(val))

    def __str__(self):
        out = 'Packet id=' + str(id(self)) + ' attributes:\n'
        for idx in range(len(Connection.attrs)):
            out = out + Connection.attrs[idx] + ":" + str(getattr(self, Connection.attrs[idx])) + "\n"
        return out

    def is_normal(self):
        return getattr(self, 'label') == 'normal'

    def to_training_data(self):
        data = []
        for attr in Connection.attrs[:-1]:
            data.append(getattr(self, attr))
        label = 1
        if getattr(self, Connection.attrs[-1]) == 'normal':
            label = 0
        return data, label

    def to_test_data(self):
        data = []
        for attr in Connection.attrs[:-1]:
            data.append(getattr(self, attr))
        return data

    @classmethod
    def get_type(cls, name):
        idx = Connection.attrs.index(name)
        if (1 <= idx and idx <= 3) or  idx == 41:
            return 0
        elif 24 <= idx and idx <= 30:
            return 1
        elif (33 <= idx and idx <= 41):
            return 1
        else:
            return 2


def read(path):
    with open(path, 'r') as ds:
        reader = csv.reader(ds, delimiter=',')
        fileConnections = []
        for row in reader:
            fileConnections.append(Connection(row))
        return fileConnections
