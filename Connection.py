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
	services = ['http':0, 'domain_u':1, 'gopher':2, 'kshell':3, 'pop_2':4, 'http_8001':5, 'private':6, 'efs':7,
				'netbios_ssn':8, 'ssh':9, 'smtp':10, 'klogin':11 'vmnet':12, 'daytime':13, 'ftp':14, 'aol':15,
				'tim_i':16, 'X11':17, 'netstat':18, 'uucp':19, 'pop_3':20, 'Z39_50':21, 'rje':22, 'discard':23,
				'exec':24, 'uucp_path':25, 'netbios_ns':26, 'ntp_u':27, 'shell':28, 'telnet':29, 'whois':30,
				'pm_dump':31, 'sunrpc':32, 'csnet_ns':33, 'urh_i':34, 'finger':35, 'other':36, 'eco_i':37,
				'ldap':38, 'supdup':39, 'domain':40, 'systat':41, 'nnsp':42, 'http_2784':43, 'bgp':44, 'harvest':45,
				'netbios_dgm':46, 'remote_job':47, 'ctf':48, 'imap4':49, 'urp_i':50, 'name':51, 'time':52,
				'iso_tsap':53, 'http_443':54, 'printer':55, 'echo':56, 'hostnames':57, 'auth':58, 'sql_net':59,
				'tftp_u':60, 'ecr_i':61, 'mtp':62, 'link':63, 'red_i':64, 'ftp_data':65, 'nntp':66, 'courier':67,
				'IRC':68]
	flags = ['OTH':0, 'S0':1, 'RSTOS0':2, 'REJ':3, 'SF':4, 'S2':5, 'S3':6, 'SH':7, 'RSTO':8, 'S1':9, 'RSTR':10]
	labels = ['buffer_overflow.':0, 'land.':1, 'rootkit.':2, 'perl.':3, 'multihop.':4, 'spy.':5, 'phf.':6,
			'guess_passwd.':7,'portsweep.':8, 'pod.':9, 'ipsweep.':10, 'normal.':11, 'teardrop.':12, 'loadmodule.':13,
			'satan.':14, 'back.':15,'imap.':16, 'smurf.':17,'ftp_write.':18, 'nmap.':19, 'warezclient.':20, 
			'warezmaster.':21, 'neptune.':22]

    def __init__(self, row):
        for idx, val in enumerate(row):
            # 1 -> 3 str columns, last is str label
			if (idx == 1):
				setattr(self, Connection.attrs[idx], protocol_types[val])
			elif (idx == 2):
				setattr(self, Connection.attrs[idx], services[val])
			elif (idx == 3):
				setattr(self, Connection.attrs[idx], flags[val])
			elif (idx == 41):
				setattr(self, Connection.attrs[idx], labels[val])
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
