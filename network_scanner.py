#!/usr/bin/env python

import scapy.all as scapy
import argparse, requests

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target to scan using -t or --target options, use --help for more info.")
    return options

def get_vendor(mac_address):
    r = requests.get("https://api.macvendors.com/" + mac_address)
    if r.status_code == 200:
        return r.text
    else:
        return "No matching vendor"

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)    # get an arp request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # Set the destination mac address
    arp_broadcast = broadcast/arp_req   # combine the broadcast and request to send to the network
    answered = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]    # (scapy.srp) send and respond + allow ether frame for the answered resquests
    client_list = []
    for element in answered:
        vendor = get_vendor(element[1].hwsrc)
        client_dict = {
        "ip": element[1].psrc,
        "mac": element[1].hwsrc,
        "vendor": vendor
        }
        client_list.append(client_dict)
    return client_list

def show_clients(client_list):
    x = "IP Address                MAC Address                   MAC Vendor"
    print(x)
    print("=" * (len(x) + 20))
    for element in client_list:
        print(element["ip"] + "\t\t" + element["mac"] + "\t\t" + str(element["vendor"]))

if __name__ == "__main__":
    options = get_arguments()
    target_ip = scan(options.target)
    show_clients(target_ip)
