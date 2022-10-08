import socket as sock
import urllib.request
import re

#Add more ports and services
#####################################

def get_http_banner(host):
	response = urllib.request.urlopen("http://" + host + ":80")
	if(response.getcode() == 200):
		return response.getheader("Server")
	else:
		return "Unknown version"


#Get the banner for a specific port
#Works for ports 21,22 (at least)
def get_banner(host, port, socket):
	result = None
	try:
		#If can't connect to the port or host then timeout
		socket.settimeout(10)
		socket.connect((host, port))
		result = socket.recv(1024).decode().strip()
	except:
		pass

	if(result != None):
		return result
	else:
		return "Unknown version"

def get_all_banners(host, open_ports, ports_versions, socket):
	for port in open_ports:
		if(port == 80 or port == 443):
			banner_result = get_http_banner(host)
		else:
			#Must reset the socket at every loop to avoid timeout exception
			socket = sock.socket()
			banner_result = get_banner(host, port, socket)

		ports_versions[port] = parse_banner(banner_result)

	return ports_versions

#Return only the necessary part of the banner
def parse_banner(banner):
	if(banner != None):
		if("FTP" in banner):
			try:
                                return banner.split("(")[1].split(")")[0]
                        except:
                                return "Can't retrieve version"
		#Return the default banner if there's nothing to change
		else:
			return banner

#Define and return the corresponding service to banner
def check_service_banner(banner):
	if(banner != None):
		if("OpenSSH" in banner):
			return "ssh"
		if("FTP" in banner):
			return "ftp"
	else:
		return "unknown"

#If a service is unknown then replace it by the correct one tanks to banner recognition
def replace_service_banner(ports_services, ports_versions):
	for port in ports_services:
		if(ports_services[port] == "unknown"):
			#Get the correct banner
			banner = ports_versions[port]
			service = check_service_banner(banner)
			ports_services[port] = service
	return ports_services
