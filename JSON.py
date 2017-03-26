import os
import json


def path_to_dict(path):
	d = {'name': 'RTP Analyser'}
	d['script_path']='/usr/local/bin/python RTPExtractor.py'
	d['description']='Executes a RTPExtractor python scripts and prints all incoming parameters'
	d['working_directory']=''
	pcap=[]
	for x in os.listdir(path):
		if 'pcap' in x:
			pcap.append(path+'/'+x)
	d['parameters'] = {'name': 'PCAP Name','param': '-p','description': 'list of pcaps','type': 'list','default': 'Pcaps/uac.pcap','values':pcap}

	#d['parameters']= {'name': 'PCAP Name'}
	#d['parameters']={'param':'-p'}
	#d['parameters']={'description': 'list of pcaps'}
	#d['parameters']={'type':'list'}
	#d['parameters']={'default':'Pcaps/uac.pcap'}
	#d['parameters']['values'] =
	#for x in os.listdir(path):
	#	if 'pcap' in x:
	#		d['parameters' 'values'] =path+x
	return d

def dump_to_file(path):
	data=path_to_dict(path)
	with open('Conf/runners/DRTPAnalysis.json', 'w') as outfile:
		json.dump(data,outfile)

dump_to_file('Pcaps')