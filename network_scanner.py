#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target to scan using -t or --target options, use --help for more info.")
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    response = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for element in response:
        client_dict = {
        "ip": element[1].psrc,
        "mac": element[1].hwsrc
        }
        client_list.append(client_dict)
    return client_list

def show_clients(client_list):
    x = "IP Address\t\t MAC Address\t\t Count\t Len\t MAC Vendor / Hostname"
    print(x)
    print("=" * (len(x) + (8 * 4)))
    for element in client_list:
        print(element["ip"] + "\t\t" + element["mac"])

if __name__ == "__main__":
    options = get_arguments()
    client_list = scan(options.target)
    show_clients(client_list)
