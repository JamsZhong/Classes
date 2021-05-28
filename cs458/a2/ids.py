#!/usr/bin/env python3

# Suppress warnings about missing IPv6 route and tcpdump bin
import logging
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

import sys
import ipaddress as ipa
import binascii

pcap = rdpcap(sys.argv[1])

numpackets = len(pcap)
numbytes = 0
attack = ''
details = ''
ip_lower = '10.0.0.0'
ip_upper = '10.255.255.255'
ARP_table = {}
IIS_list = ['%255c', '%25%35%63', '%c0%af', '%252f', '%%35c', '%%35%63', '%c1%1c', '%c1%9c', '%c1%af',
            '%e0%80%af', '%f0%80%80%af','%f8%80%80%80%af', '%fc%80%80%80%80%af', '\%e0\%80\%af']
HTTP_requests = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']

with open('sinkholes.txt') as f:
    sinkholes = f.read().splitlines()

def validate_IP(lower, upper, ip):
    if(ipa.IPv4Address(lower) <= ipa.IPv4Address(ip) and ipa.IPv4Address(upper) >= ipa.IPv4Address(ip)):
        return True
    else:
        return False

for packet in pcap:
    numbytes += len(packet)

    packet_type = packet[Ether].type

    # IPv4 Packet
    if(packet_type == 2048):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Check IP range
        if(not(validate_IP(ip_lower, ip_upper, src_ip) or validate_IP(ip_lower, ip_upper, dst_ip))):
            attack = "Spoofed IP address"
            details = f"src:{src_ip}, dst:{dst_ip}"
            print(f"[{attack}]: {details}")
            if(packet[IP].proto == 17 and packet.payload.dport == 123 and bytes(packet[UDP].payload)[3] == 42):
                attack = "NTP DDoS"
                details = f"vic:{src_ip}, srv:{dst_ip}"
                print(f"[{attack}]: {details}")
        # TCP Packet
        if(packet[IP].proto == 6):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if(not validate_IP(ip_lower, ip_upper, src_ip) and validate_IP(ip_lower, ip_upper, dst_ip) and packet[TCP].flags == 0x002):
                attack = "Attempted server connection"
                details = f"rem:{src_ip}, srv:{dst_ip}, port:{dport}"
                print(f"[{attack}]: {details}")
            elif(not validate_IP(ip_lower, ip_upper, dst_ip) and validate_IP(ip_lower, ip_upper, src_ip) and packet[TCP].flags == 0x012):
                attack = "Accepted server connection"
                details = f"rem:{dst_ip}, srv:{src_ip}, port:{sport}"
                print(f"[{attack}]: {details}")
            if(packet[TCP].dport == 80 and packet[TCP].flags == 0x018):
                HTTP_protocol_str = packet[Raw].load.decode('utf-8', errors = 'ignore')
                start_index = -1
                for command in HTTP_requests:
                    start_index = HTTP_protocol_str.find(command)
                    if(start_index != -1):
                        break
                end_index = HTTP_protocol_str.find("HTTP")

                if(start_index == -1 or end_index == -1):
                    continue
                else:
                    HTTP_protocol_str = str.lower(HTTP_protocol_str[start_index:end_index])
                    for IIS in IIS_list:
                        if(HTTP_protocol_str.find(IIS) != -1):
                            attack = "Unicode IIS exploit"
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst
                            details = f"src:{src_ip}, dst:{dst_ip}"
                            print(f"[{attack}]: {details}")
                            break
        # UDP Packet
        if(packet[IP].proto == 17 and packet.payload.sport == 53):
            if(packet[DNS].ancount):
                ip_addr = packet[DNSRR][0].rdata
                for sinkhole in sinkholes:
                    if(ip_addr == sinkhole):
                        name = (packet[DNSRR][0].rrname).decode('UTF-8')[:-1]
                        attack = "Sinkhole lookup"
                        details = f"src:{dst_ip}, host:{name}, ip:{ip_addr}"
                        print(f"[{attack}]: {details}")
                        break

    # ARP Packet
    elif(packet_type == 2054 and packet[ARP].op == 2):
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc.upper()
        if(not src_ip in ARP_table):
            ARP_table[src_ip] = src_mac
        elif(ARP_table[src_ip] != src_mac):
            attack = "Potential ARP spoofing"
            details = f"ip:{src_ip}, old:{ARP_table[src_ip]}, new:{src_mac}"
            print(f"[{attack}]: {details}")
            ARP_table[src_ip] = src_mac
                    
print(f"Analyzed {numpackets} packets, {numbytes} bytes")