#! /bin/python3
import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=lambda x: x.show())


sniff("eth0")
