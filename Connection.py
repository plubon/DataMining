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
    # columns 1, 2, 3, and label enumerations         
    protocol_types = {'tcp':0,'udp':1, 'icmp':2}
    
    services = {'eco_i':0, 'name':1, 'telnet':2, 'sunrpc':3, 'ftp':4, 'courier':5, 'klogin':6, 'harvest':7,
    'domain_u':8, 'pop_3':9, 'netstat':10, 'link':11, 'X11':12, 'IRC':13, 'netbios_ssn':14, 'tftp_u':15, 'ldap':16,
    'kshell':17, 'uucp_path':18, 'http':19, 'aol':20, 'supdup':21, 'shell':22, 'iso_tsap':23, 'red_i':24, 'login':25,
    'discard':26, 'ftp_data':27, 'rje':28, 'printer':29, 'Z39_50':30, 'sql_net':31, 'daytime':32, 'netbios_ns':33,
    'http_443':34, 'nntp':35, 'ctf':36, 'efs':37, 'whois':38, 'urh_i':39, 'auth':40, 'ecr_i':41, 'urp_i':42,
    'http_2784':43, 'nnsp':44, 'ntp_u':45, 'other':46, 'remote_job':47, 'ssh':48, 'time':49, 'tim_i':50, 'echo':51,
    'pop_2':52, 'domain':53, 'private':54, 'netbios_dgm':55, 'hostnames':56, 'finger':57, 'http_8001':58, 'smtp':59,
    'uucp':60, 'exec':61, 'vmnet':62, 'mtp':63, 'pm_dump':64, 'bgp':65,'csnet_ns':66, 'systat':67, 'gopher':68, 'imap4':69}
    
    flags = {'OTH':0, 'S0':1, 'RSTOS0':2, 'REJ':3, 'SF':4, 'S2':5, 'S3':6, 'SH':7, 'RSTO':8, 'S1':9, 'RSTR':10}
    labels = {'buffer_overflow.':0, 'land.':1, 'rootkit.':2, 'perl.':3, 'multihop.':4, 'spy.':5, 'phf.':6,
    'guess_passwd.':7,'portsweep.':8, 'pod.':9, 'ipsweep.':10, 'normal.':11, 'teardrop.':12, 'loadmodule.':13,
    'satan.':14, 'back.':15,'imap.':16, 'smurf.':17,'ftp_write.':18, 'nmap.':19, 'warezclient.':20, 
    'warezmaster.':21, 'neptune.':22}

    def __init__(self, row):
        for idx, val in enumerate(row):
            # 1 -> 3 str columns, last is str label
            if (idx == 1):
                setattr(self, Connection.attrs[idx], Connection.protocol_types[val])
            elif (idx == 2):
                setattr(self, Connection.attrs[idx], Connection.services[val])
            elif (idx == 3):
                setattr(self, Connection.attrs[idx], Connection.flags[val])
            elif (idx == 41):
                setattr(self, Connection.attrs[idx], Connection.labels[val])
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
