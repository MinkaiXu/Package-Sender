import os
import socket
import struct
from scapy.all import *
from PacketProcess import *
import SockPcap
import array


class sockARP(object):
    def __init__(self, sip='127.0.0.1', dip='127.0.0.1', sm="00:00:00:00:00:00",
                 dm="ff:ff:ff:ff:ff:ff", mode=1):
        self.ARP_HardType = 1
        self.ARP_ProtoType = 0x0800
        self.ARP_HardSize = 6
        self.ARP_ProtoSize = 4
        self.ARP_OPcode = mode
        self.ARP_SrcMac = sm
        self.ARP_SrcIP = sip
        self.ARP_DstMac = dm
        self.ARP_DstIP = dip

    def pack(self):
        HPart1 = struct.pack("!HHBBH", self.ARP_HardType, self.ARP_ProtoType, self.ARP_HardSize,
                             self.ARP_ProtoSize, self.ARP_OPcode)
        HSrcIP = struct.pack("!4s", socket.inet_aton(self.ARP_SrcIP))
        HDstIP = struct.pack("!4s", socket.inet_aton(self.ARP_DstIP))
        HSrcMac = hexinput(Mac_decode(self.ARP_SrcMac))
        HDstMac = hexinput(Mac_decode(self.ARP_DstMac))
        return HPart1 + HSrcMac + HSrcIP + HDstMac + HDstIP

    def decode(self):
        self.pack()
        s = ""
        s = s + "Address Resolution Protocol "
        if (self.ARP_OPcode == 1):
            s = s + "(Request) \n"
            s = s + "Who has " + self.ARP_DstIP + "? Tell " + self.ARP_SrcIP + "\n"
        elif (self.ARP_OPcode == 2):
            s = s + "(Reply) \n"
            s = s + self.ARP_SrcIP + " is at " + self.ARP_SrcMac + "\n"
        else:
            s = s + "(Other) \n"
        s = s + "\t Hardware Type : "
        if (self.ARP_HardType == 1):
            s = s + "Ethernet, "
        else:
            s = s + "Other, "
        s = s + str(self.ARP_HardType) + \
            "(" + inttohex(self.ARP_HardType, 4) + ") \n"
        s = s + "\t Protocol Type : "
        if (self.ARP_ProtoType == 0x0800):
            s = s + "IPv4, "
        elif (self.ARP_ProtoType == 0x08DD):
            s = s + "IPv6, "
        else:
            s = s + "Other, "
        s = s + str(self.ARP_ProtoType) + \
            "(" + inttohex(self.ARP_ProtoType, 4) + ") \n"
        s = s + "\t Hardware Size : " + \
            str(self.ARP_HardSize) + "(" + inttohex(self.ARP_HardSize, 2) + ")\n"
        s = s + "\t Protocol Size : " + \
            str(self.ARP_ProtoSize) + \
            "(" + inttohex(self.ARP_ProtoSize, 2) + ")\n"
        s = s + "\t Opcode: "
        if (self.ARP_OPcode == 1):
            s = s + "1 (Request) "
        elif (self.ARP_OPcode == 2):
            s = s + "2 (Reply) "
        else:
            s = s + "(Other) "
        s = s + "(" + inttohex(self.ARP_OPcode, 4) + ")\n"
        s = s + "\t Sender MAC Address : " + self.ARP_SrcMac + \
            "(" + Mac_decode(self.ARP_SrcMac) + ") \n"
        s = s + "\t Sender IP Address : " + self.ARP_SrcIP + \
            "(" + addresstohex(self.ARP_SrcIP) + ") \n"
        s = s + "\t Target MAC Address : " + self.ARP_DstMac + \
            "(" + Mac_decode(self.ARP_DstMac) + ") \n"
        s = s + "\t Target IP Address : " + self.ARP_DstIP + \
            "(" + addresstohex(self.ARP_DstIP) + ") \n"
        return s

    def socksendARP(self):
        ARPsender = ARP(self.pack())

        send(ARPsender)

    def appendPCAP(self, filename):
        tmp = Ether(type=0x0806) / self.pack()
        SockPcap.PCAPwrite(filename, tmp)
