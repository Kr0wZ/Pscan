#!/usr/bin/env python3
#encoding: utf-8

import optparse
import sys
import re
import socket
import subprocess
import time
import random
from scapy.all import *
import prettytable

#Add python colors


class Pscan():
	def __init__(self):
		self.parser = None
		self.host = None
		self.hostname = "unknown"
		self.port_range = None
		self.scan_type = None
		self.supported_scan_types = ["syn", "xmas", "fin", "null", "tcp", "ping", "ack"]
		self.supported_scan_types_short = ["S", "X", "F", "N", "T", "P", "A"]
		self.verbose = False
		self.open_ports = list()
		self.os_detection = False
		self.number_of_open_ports = 0
		self.number_of_scanned_ports = 0
		self.start_time = 0

	#Build the parser
	def build_opt_parser(self):
		#Ceating the parser and adding usage
		self.parser = optparse.OptionParser(add_help_option=False, usage="usage: %prog [options] arg1", version="Pscan 1.5")
		#Adding multiple options
		self.parser.add_option("-H", "--host", dest="host", type="string", action="callback", callback=self.check_ip, help="Host to scan. Must be like this format : \"192.168.1.1\" (without the quotes)")
		self.parser.add_option("-p", "--port", dest="port_range", default="1-1024", action="callback", callback=self.check_port_range, type="string", help="Port(s) number(s) to scan (default is the first 1024 ports)")
		self.parser.add_option("-s", "--scan", dest="scan_type", default="syn", action="callback", callback=self.check_scan_type, type="string", help="Type of scan. -h or --help to see the supported ones")
		self.parser.add_option("-O", "--OS", dest="os_detection", default=False, action="store_true", help="Try to detect the scanning OS")
		#Verbose option just display content directly when it receives it. If not verbose the result is displayed at the end of scan
		self.parser.add_option('-v', '--verbose', dest='verbose', default=False ,action='store_true', help='Verbose output')
		#We modify the help to add more information at the end (epilog)
		self.parser.add_option('-h', '--help', dest='help', action='store_true', help='Show this help and exit the program')

		#Add an option for services verion
		#Possibility to specify a network mask
		#Add option to specify output file to write results
		#Add option to specify input file if multiple hosts
		#############################

		(options, args) = self.parser.parse_args()
		

		#DO NOT CHANGE THE ORDER OF OPTIONS.HOST AND OPTIONS.HELP
		#ADD EVERYTHING BELOW THE IF CONDITION OF OPTIONS.HELP

		if(options.verbose):
			self.verbose = True

		#Update the host value after the callback. If the callback fails the value is the default one (None) and then will trigger th if condition
		options.host = self.host
		if(not options.host and not options.help):
			self.parser.error("Error you must specify a host to scan\n\n-h or --help to see the help")

		#Must call help only if there are not other options set
		if(options.help):
			if(options.host):
				self.parser.error("Error you can only specify -h or --help when no other options are set")
			#Print the help menu as always
			#self.parser.print_usage()
			self.parser.print_help()
			#Adding more stuff at the end
			print("\nSupported scan types:\n  TCP SYN (--scan=syn / -sS)\n  TCP connect (--scan=tcp / -sT)\n  XMAS (--scan=xmas / -sX)\n  UDP (--scan=udp / -sU)\n  ...\n")
			print("Examples:\n  python3 pscan.py -H 127.0.0.1\n  python3 pscan.py -H 127.0.0.1 -p 1-65535\n  python3 pscan.py -H 127.0.0.1 -p 80\n  python3 pscan.py -H 127.0.0.1 -sS\n  python3 pscan.py -H 127.0.0.1 --scan=tcp -p20-50\n")
			sys.exit()
		

		if(options.os_detection):
			self.os_detection = True
		#If port_range is not specified then the callback isn't called and we attribute the default value (same for scan_type)

		if((self.scan_type == "ping" or self.scan_type == "P") and self.port_range != None):
			self.parser.error("Error you cannot specify a port when using ping scan. -h or --help for further informations")

		if(len(args) != 0):
			self.parser.error("Error unknown argument. Type -h or --help to see help")

	#The callback to check ip address validity
	def check_ip(self, option, opt, value, parser):
		if(value == None):
			self.parser.error("Error you must specify a host to scan\n\n-h or --help to see the help")

		try:
			ip = value.split('.')
			#Check if IP address has bytes between 0 and 255
			if(len([byte for byte in ip if(int(byte) >= 0 and int(byte) <= 255)]) != 4):
				raise ValueError()
		except ValueError:
			self.parser.error("Error you must specify a valid IP address to scan\n\n-h or --help to see the help")
			sys.exit()

		self.host = value

	#Callback to check if the port range is valid
	def check_port_range(self, option, opt, value, parser):
		try:
			ports = value.split('-')	

			if(len(ports) > 2 or '' in ports): #The '' in ports is triggered when -p -45 or -p 45- for example
				raise ValueError()
		
			#If the length of ports which are correct is different from the number of initial ports then it means at least one port isn't between 1 and 65535
			if(len([port for port in ports if(int(port) >= 1 and int(port) <= 65535)]) != len(ports)):
				raise ValueError()

			if(len(ports) == 2):
				#Check if first number is greater than the second one. In this case change their order.
				if(int(ports[0]) > int(ports[1])):
					#Swap them
					ports[0], ports[1] = ports[1], ports[0]

				#Check if the two numbers are the same. In this case remove one.
				if(int(ports[0]) == int(ports[1])):
					ports.pop()

		except ValueError:
			self.parser.error("Error you must specify a valid port range to scan (between 1 and 65535)\n\n-h or --help to see the help")

		self.port_range = '-'.join(ports)

	#Callback to check scan types validity
	def check_scan_type(self, option, opt, value, parser):
		#Check if the option is --scan or -s to use the correct list
		if(opt == "--scan" and not value in self.supported_scan_types):
			self.parser.error("Error you must specify a valid scan type\n\n-h or --help to see the help")
		elif(opt == "-s" and not value in self.supported_scan_types_short):
			self.parser.error("Error you must specify a valid scan type\n\n-h or --help to see the help")
		else:
			self.scan_type = value

	#Check the OS version by using the ttl
	def check_os_version(self, ttl):
		if(ttl == 64):
			return "Linux"
		elif(ttl == 128):
			return "Windows"
		elif(ttl == 256):
			return "Solaris/AIX"
		else:
			return "Unknown"

	#Return a list of integers corresponding to the ports to scan
	def parse_ports(self, ports):
		#Defining the default value (if -p is not specified in the options)
		if(ports == None):
			ports = "1-1024"
			self.port_range = ports
		ports_to_scan = [int(port) for port in ports.split('-')]
		#If only one port, can't iterate through it
		if(len(ports_to_scan) == 1):
			return ports_to_scan
		return [port for port in range(ports_to_scan[0], ports_to_scan[1]+1)]


	#Called when option -O is specified
	def determining_os_version(self):

		if(self.verbose):
			print("Determining OS version ... It can takes several minutes ... ")

		count = 0
		ttl = 0
		total_ttl = 0
		answer, unanswer = sr(IP(dst=self.host, ttl=(1,30))/ICMP(), verbose=0, timeout=5)
		if(len(answer) > 0):
			for i in answer:
				for j in i:
					if(j[IP].src == self.host):
						if(j[ICMP].type == 0):  #Reply echo
							#print("ttl : " + str(j[IP].ttl))
							ttl = j[IP].ttl
							count += 1
		else:
			total_ttl = 999  #Define a big number to match with unknown os

		if(total_ttl == 0):  #If 0 means that the previous else condition wasn't triggered 
			total_ttl = 30 - count + ttl

		if(self.verbose):
			print("Remote host is " + self.check_os_version(total_ttl))


	def resolve_hostname(self):
		try:
			#On récupère le nom d'hote
			hostname_resolve = socket.gethostbyaddr(self.host)[0]
			self.hostname = hostname_resolve

		except(socket.herror):
			self.hostname = "unknown"

	#At the end of scan search the corresponding ports in the text file
	#Return a dict with the correct matches
	def corresponding_ports(self):
		services = {}
		#Store the previous line if we don't find the port in the file and if the next line is greater than the researched one
		previous_line = ""
		#The self.open_ports variable must be sorted to work correctly
		with open("ports_list.txt", "r") as ports_file:
			for port in self.open_ports:
				for line in ports_file:
					#If line or the previous line starts with the port number it's ok
					if(line.startswith(str(port) + " ") or previous_line.startswith(str(port) + " ")):	#Adding space to match the exact ports
						services[port] = line.split(' ')[1].split('\n')[0] 	#Store the port number and service name into a dictionnary
						break
					#Else if the port number is greater than the one we search for it means it's not in the file and then break
					elif(int(line.split(" ")[0]) > port):
						services[port] = "unknown"
						previous_line = line
						break

		return services

	def scan(self):

		#To print the time elapsed during the scan (at the end)
		self.start_time = time.time()

		#If option is set then execute function
		if(self.os_detection):
			self.determining_os_version()

		if(self.verbose):
			self.resolve_hostname()
			print("Scanning host : " + str(self.hostname))
		
		#Default if no -s or --scan option
		if(self.scan_type == None):
			self.scan_type = "syn"

		#Get a list of ports (to scan) only if not a ping scan
		if(self.scan_type != "ping" and self.scan_type != "P"):
			ports = self.parse_ports(self.port_range)

		#Creating the IP layer
		ip_layer = IP(dst=self.host)

		#----------------------------------------------------------------------------------------------------------------
		#|													SYN SCAN     					 							|
		#----------------------------------------------------------------------------------------------------------------

		if(self.scan_type == "syn" or self.scan_type == "S"):
			if(self.verbose):
				print("TCP SYN scan")
			#Creating TCP layer
			tcp_layer = TCP(dport=ports, flags="S")
			#Determine if there are multiple ports (range) or not
			if(len(ports) > 1):
				#How to define the correct timeout ? With the number of ports to scan ??? (if < 256 -> 5 seconds, if 1024 -> 10 seconds ???)
				answer, unanswer = sr(ip_layer/tcp_layer, timeout=10, verbose=0)
				for frame in answer:
					self.number_of_scanned_ports += 1
					for layer in frame:
						if(layer.src == self.host):
							if(layer[TCP].flags == "SA"): 		#SA is open (SYN/ACK) -> RA not (RST/ACK)
								if(self.verbose):
									print("[+] Open port : " + str(layer[TCP].sport))
								self.open_ports.append(layer[TCP].sport)
								self.number_of_open_ports += 1
			else:
				#sr1 (send/receive 1) to just get the first packet received
				answer = sr1(ip_layer/tcp_layer, verbose=0) 
				
				if(answer[TCP].flags == "SA"):			#SA is open (SYN/ACK) -> RA not (RST/ACK)
					self.open_ports.append(answer[TCP].sport)
					self.number_of_open_ports += 1
			
				self.number_of_scanned_ports += 1


		#----------------------------------------------------------------------------------------------------------------
		#|												TCP CONNECT SCAN (used for service enum)						|
		#----------------------------------------------------------------------------------------------------------------

		#This is a three way handshake
		#SYN (seq number = X) -> SYN/ACK (seq number = y / ack number = X+1) -> ACK (seq number = X / ack number = y+1)

		if(self.scan_type == "tcp" or self.scan_type == "T"):
			if(self.verbose):
				print("TCP Connect scan")
			#Creating TCP layer with sequence number (whatever it is)
			#Can't add multiple ports in TCP layer for this 3-way handshake. Must iterate on each ports (slower)
			tcp_layer = TCP(flags="S", seq=100)
			for port in ports:

				#Reset the flag -> "S" for each iteration
				tcp_layer.flags = 'S'
				tcp_layer.dport = port
				#sr1 (send/receive 1) to just get the first packet received
				synack_pkt = sr1(ip_layer/tcp_layer, verbose=0) 
				

				#Sending a ACK pkt and adding +1 to ack number
				tcp_layer.ack = synack_pkt.seq + 1
				tcp_layer.seq = synack_pkt.ack
				tcp_layer.flags = 'A'		#'A' flag for ACK 
				
				final_pkt = sr1(ip_layer/tcp_layer, verbose=0)
				#At this moment we wait for the banner
				
				if(synack_pkt[TCP].flags == "SA"):			#SA is open (SYN/ACK) -> RA not (RST/ACK)
					if(self.verbose):
						print("[+] Open port : " +  str(port))
					self.open_ports.append(final_pkt[TCP].sport)
					self.number_of_open_ports += 1
			
				self.number_of_scanned_ports += 1



		#----------------------------------------------------------------------------------------------------------------
		#|													FIN SCAN 													|
		#----------------------------------------------------------------------------------------------------------------

		if(self.scan_type == "fin" or self.scan_type == "F"):
			if(self.verbose):
				print("TCP FIN scan")
			#Create the TCP layer
			tcp_layer = TCP(flags="F")
			
			for port in ports:
				tcp_layer.dport = port
				#sr1 (send/receive 1) to just get the first packet received
				#Timeout because if port is open then we will never get a response. 
				answer = sr1(ip_layer/tcp_layer, timeout=1, verbose=0) 
				
				if(answer == None):	  	#If None means timeout has been triggered -> no response = open else closed/filtered
					if(self.verbose):
						print("[+] Open port : " + str(port))
					self.open_ports.append(port)
					self.number_of_open_ports += 1
			
				self.number_of_scanned_ports += 1


		#----------------------------------------------------------------------------------------------------------------
		#|													NULL SCAN 													|
		#----------------------------------------------------------------------------------------------------------------

		#Be careful ! It can show false positives !

		#With no flags set
		if(self.scan_type == "null" or self.scan_type == "N"):
			if(self.verbose):
				print("NULL scan")
			#Create the TCP layer
			tcp_layer = TCP(flags="")
			
			for port in ports:
				tcp_layer.dport = port
				#sr1 (send/receive 1) to just get the first packet received
				#Timeout because if port is open then we will never get a response. 
				answer = sr1(ip_layer/tcp_layer, timeout=2, verbose=0) 
			
				if(answer == None):
					if(self.verbose):
						print("[+] Open port : " + str(port))
					self.open_ports.append(port)
					self.number_of_open_ports += 1
			
				self.number_of_scanned_ports += 1



		#----------------------------------------------------------------------------------------------------------------
		#|													XMAS SCAN 													|
		#----------------------------------------------------------------------------------------------------------------

		if(self.scan_type == "xmas" or self.scan_type == "X"):
			if(self.verbose):
				print("XMAS scan")
			#Flags PSH FIN URG -> P, F, U
			#Create the TCP layer
			tcp_layer = TCP(flags="PFU")
			
			for port in ports:
				tcp_layer.dport = port
				#sr1 (send/receive 1) to just get the first packet received
				#Timeout because if port is open then we will never get a response. 
				answer = sr1(ip_layer/tcp_layer, timeout=2, verbose=0) 
			
				if(answer == None):
					if(self.verbose):
						print("[+] Open port : " + port)
					self.open_ports.append(port)
					self.number_of_open_ports += 1
			
				self.number_of_scanned_ports += 1


		#----------------------------------------------------------------------------------------------------------------
		#|													ACK SCAN 													|
		#----------------------------------------------------------------------------------------------------------------

		#This scan cannot tells if a port is open or not but only tells if it's filtered or not

		if(self.scan_type == "ack" or self.scan_type == "A"):
			if(self.verbose):
				print("ACK scan")
			#Create the TCP layer
			tcp_layer = TCP(flags="A")
			
			for port in ports:
				tcp_layer.dport = port
				#sr1 (send/receive 1) to just get the first packet received
				#Timeout because if port is open then we will never get a response. 
				answer = sr1(ip_layer/tcp_layer, timeout=2, verbose=0) 

				if(answer[TCP].flags == "R"):
					print("Port " + str(port) + " is not filtered")
				else:
					print("Filtered")

				self.number_of_scanned_ports += 1


		#----------------------------------------------------------------------------------------------------------------
		#|													PING SCAN 													|
		#----------------------------------------------------------------------------------------------------------------

		#Don't know why I can't ping myself (and 127.0.0.1)

		if(self.scan_type == "ping" or self.scan_type == "P"):
			if(self.verbose):
				print("Ping scan")
			answer, unaswer = sr(ip_layer/ICMP(), timeout=2, verbose=0)
			#If there is an answer the host might be up, else not
			if(len(answer) > 0):
				for frame in answer:
					for layer in frame:
						if(layer.src == self.host):
							if(layer[ICMP].type == 0): #Reply 0 is alive
								print("Host is alive")
			else:
				print("Host is down")


	def print_results(self):
		table = prettytable.PrettyTable()
		table.field_names = ["Port", "Status", "Name"]

		corresponding_ports = self.corresponding_ports()

		for port in corresponding_ports:
			table.add_row([port, "open", corresponding_ports[port]])

		print("\n" + str(table))

		print("\nScan finished in {:.2f} seconds - {} scanned port(s) - {} opened port(s)".format(time.time() - self.start_time, str(self.number_of_scanned_ports), str(self.number_of_open_ports)))
		
		#print(self.open_ports)
		#print(self.corresponding_ports())
	#Create function to print results



if(__name__ == "__main__"):

	pscan = Pscan()
	pscan.build_opt_parser()
	pscan.scan()
	pscan.print_results()
