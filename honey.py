#!/usr/bin/env python3

import time
import socket, sys
from struct import *
import nmap
import requests
import json

def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
    
def getInput():
	host = input('IP Address: ')
	while True:
		try:
			port = int(input('Port: '))
		except TypeError:
			print('Error: Invalid port number.')
			continue
		else:
			if (port < 1) or (port > 65535):
				print('Error: Invalid port number.')
				continue
			else:
				return (host, port)

def writeLog(client, data=''):
	separator = '='*50
	fopen = open('./honey.txt', 'a') 
	fopen.write('Time: {}\nIP: {}\nPort: {}\nData: {}\n{}\n\n'.format(time.ctime(), client[0], client[1], data.decode('utf-8'), separator))
	fopen.close()

def main(host, port):
	print('Starting honeypot!')
	findex = open('src/main/index.html','r')
	fdata = findex.read()
	findex.close()
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	s.bind((host, port))
	s.listen()
	tmpAdd = []
	while True:
		(insock, address) = s.accept()
		if address[0] not in tmpAdd:
			tmpAdd.append(address[0])
			print('Connection from: {}:{}'.format(address[0], address[1]))

			try:

				data = insock.recv(1000)
				rmip = "{}:{}".format(address[0],address[1])
				rmdev = data.decode('utf-8').split("User-Agent: ")[1].split("\n")[0].split("(")[1].split(")")[0]
				
				f = fdata.split('<div id="devinfo">')
				f[0] += '<div id="devinfo">'
				fresp = f[0] + "<p> IP : <span>" + rmip + "</span><br/>\nDevice : <span>" + rmdev + "<span><br/>" + f[1]

				
				insock.send(bytes(fresp,'utf-8'))
				insock.close()
			except socket.error as e:
				writeLog(address)
			else:
				writeLog(address, data)
			postreq = {
				'ip': address[0],
				'mac': '',
				'device': rmdev,
				'time' : '',
				'elapsedtime' : '',
				'vendor': '', 
				'state': '',
				'reason': '',
				'uphosts': '',
				'downhosts': '',
				'totalhosts': '',
				'ports': [],
				'pstates': []
			}
			nm=nmap.PortScanner()
			nm.scan(address[0], '0-65535')
			for proto in nm[address[0]].all_protocols():
				print('----------------------------')
				print('Protocol : %s' %proto)
				lport = nm[address[0]][proto].keys()
				for port in lport:
					pstate = nm[address[0]][proto][port]['state']
					postreq['ports'].append(port)
					postreq['pstates'].append(pstate)
					print('Port : %s\tState : %s'%(port,pstate))

			res = nm.scan(hosts=address[0], arguments='-n -sP -PE -sV -PA"0-65535"')
			print(type(res),res)
			postreq['mac'] = res['scan'][address[0]]['addresses']['mac']
			postreq['time'] = res['nmap']['scanstats']['timestr']
			postreq['elapsedtime'] = res['nmap']['scanstats']['elapsed']
			postreq['reason'] = res['scan'][address[0]]['status']['reason']
			postreq['state'] = res['scan'][address[0]]['status']['state']
			postreq['vendor'] = res['scan'][address[0]]['vendor'][postreq['mac']]
			postreq['uphosts'] = res['nmap']['scanstats']['uphosts']
			postreq['downhosts'] = res['nmap']['scanstats']['downhosts']
			postreq['totalhosts'] = res['nmap']['scanstats']['totalhosts']

			if len(postreq['ports']) == 0:
				postreq['ports'].append('None')
				postreq['pstates'].append('NA')

			print('\n\n\n---------------\n',postreq,'\n--------------\n')
			# print('\n\n\n---------------\n',json.dumps(postreq),'\n--------------\n')

			resp = requests.post(url="http://localhost:8080/intruder",data = postreq);
			print(resp)
			#print(nm.csv())

        

if __name__=='__main__':
	try:
		stuff = getInput()
		main(stuff[0], stuff[1])
	except KeyboardInterrupt:
		print('Bye!')
		exit(0)
	except BaseException as e:
		print('Error: %s' % (e))
exit(1)
