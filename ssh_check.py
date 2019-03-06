# Name		: SSH Audit Check v0.9,dated 06/03/2019
# Copyright	: 
#	Some internet libraries/components and public codes was used under GNU General Public License v3.0
#	Please refer https://www.cisecurity.org/cis-benchmarks/ for CIS orgCIS Benchmarks Checklist copyright 
# Contact	: If having any comments or issues, please contatct: truonggiang.n.le@gmail.com
#================================================================================
# WARNING: BY USING THIS TOOL, WILL TAKE ACCOUNTABLE FOR ALL RISKS WITH YOUR SYSTEM. 
#================================================================================

# Component or Libarary import
import paramiko
import cmd
import time
import sys
import csv
import os
import re
import getpass

# Variable declare and input parameters
cmd_file = raw_input('Enter file name of checklist command (example: checklist.txt): ')
endpointIPs = raw_input('Enter file name of ip list (example: iplist.txt): ')
username = raw_input('Enter SSH credential (example: audit): ')	 
password = getpass.getpass('Enter SSH password (example: xxxxxx): ')
buff = ''
resp = ''

#Read IP of endpoint from file
ip_file = open(endpointIPs, "r")
ip_list = ip_file.read().splitlines()

#Read audit command file and put to list
text_file = open(cmd_file, "r")
cmd_list = text_file.read().splitlines()
text_file.close()

#Run audit command list with IP endpoint in IP list
for hostip in ip_list:
	#SSH conneciton initial
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostip, username=username, password=password)
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	#Open SSH session
	chan = ssh.invoke_shell()

	#Turn off banner paging
	chan.send('terminal length 0\n')
	time.sleep(2)
	resp = chan.recv(15000)
	output = resp.decode('utf-8').split(',')
	#print (''.join(output))
	
	#Get hostname of device from host IP
	chan.send('show run view full | incl hostname')
	chan.send('\n')
	time.sleep(3)
	resp = chan.recv(15000)
	output = resp.decode('utf-8').splitlines()
	hostname = output[-1]

	#Open file TXT to save output
	output_file = hostname + '.txt'
	file = open(output_file, 'w')

	#Save output of command list to file
	for cmd in cmd_list:
		chan.send(cmd.decode('utf-8'))
		chan.send('\n')
		time.sleep(2)
		resp = chan.recv(15000)
		#output = resp.decode('utf-8').split(',')
		output = resp.decode('utf-8')
		output = re.sub(hostname,'',output)
		output_all = filter(lambda x: not re.match('\n', x), output)
		file.write(''.join(output_all))
		print (''.join(output))

	#Clean before exit SSH session
	file.close() 
	ssh.close()
	
# === END ===