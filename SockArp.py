import os
import socket
import struct
from scapy.all import *
from PacketProcess import *
import SockPcap
import array

class sockARP(object):
    def __init__(self, sip='127.0.0.1', dip='127.0.0.1', sm = "00:00:00:00:00:00",
                 dm = "ff:ff:ff:ff:ff:ff", mode = 1):
        self.ARP_HardType                = 1           # 16bit
        self.ARP_ProtoType               = 0x0800      # 16bit
        self.ARP_HardSize                = 6           #  8bit
        self.ARP_ProtoSize               = 4           #  8bit
        self.ARP_OPcode                  = mode        # 16bit
        self.ARP_SrcMac                  = sm          # 48bit
        self.ARP_SrcIP                   = sip         # 32bit
        self.ARP_DstMac                  = dm          # 48bit
        self.ARP_DstIP                   = dip         # 32bit

    # pack is used to generate the whole packet (sendp in automatic Ethernet head)
    def pack(self):
        HPart1 = struct.pack("!HHBBH",self.ARP_HardType,self.ARP_ProtoType,self.ARP_HardSize,
                             self.ARP_ProtoSize,self.ARP_OPcode)   # first five elements of ARP head(64bits)
        HSrcIP = struct.pack("!4s",socket.inet_aton(self.ARP_SrcIP))    # SrcIP bytes of ARP head(32bits)
        HDstIP = struct.pack("!4s", socket.inet_aton(self.ARP_DstIP))   # DstIP bytes of ARP head(32bits)
        HSrcMac = hexinput(stupidDecodeMac(self.ARP_SrcMac))        # SrcMac bytes of ARP head(48bits)
        HDstMac = hexinput(stupidDecodeMac(self.ARP_DstMac))        # DstMac bytes of ARP head(48bits)
        return HPart1 + HSrcMac + HSrcIP + HDstMac + HDstIP

    # decode is used to demonstrate the ARP packet
    def decode(self):
        self.pack()
        s = ""
        s = s + "Address Resolution Protocol "
        # here is description of this Protocol
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
        s = s + str(self.ARP_HardType) + "(" + inttohex(self.ARP_HardType,4) + ") \n"
        s = s + "\t Protocol Type : "
        if (self.ARP_ProtoType == 0x0800):
            s = s + "IPv4, "
        elif (self.ARP_ProtoType == 0x08DD):
            s = s + "IPv6, "
        else:
            s = s + "Other, "
        s = s + str(self.ARP_ProtoType) + "(" + inttohex(self.ARP_ProtoType, 4) + ") \n"
        s = s + "\t Hardware Size : " + str(self.ARP_HardSize) + "(" +  inttohex(self.ARP_HardSize, 2) + ")\n"
        s = s + "\t Protocol Size : " + str(self.ARP_ProtoSize) + "(" + inttohex(self.ARP_ProtoSize, 2) + ")\n"
        s = s + "\t Opcode: "
        if (self.ARP_OPcode == 1):
            s = s + "1 (Request) "
        elif (self.ARP_OPcode == 2):
            s = s + "2 (Reply) "
        else:
            s = s + "(Other) "
        s = s +  "(" + inttohex(self.ARP_OPcode, 4) + ")\n"
        s = s + "\t Sender MAC Address : " + self.ARP_SrcMac + "(" + stupidDecodeMac(self.ARP_SrcMac) + ") \n"
        s = s + "\t Sender IP Address : " + self.ARP_SrcIP + "(" + addresstohex(self.ARP_SrcIP) + ") \n"
        s = s + "\t Target MAC Address : " + self.ARP_DstMac + "(" + stupidDecodeMac(self.ARP_DstMac) + ") \n"
        s = s + "\t Target IP Address : " + self.ARP_DstIP + "(" + addresstohex(self.ARP_DstIP) + ") \n"
        return s

    # socksendARP is used to send to ARP packet
    def socksendARP(self):
        ARPsender = ARP(self.pack())
        #print hexdump(ARPsender)
        send(ARPsender)

    # appendPCAP is used to write the packet into a file
    def appendPCAP(self,filename):
        tmp = Ether(type=0x0806) / self.pack()
        SockPcap.PCAPwrite(filename,tmp)
'''
s = sockARP("6.7.8.9","192.168.1.102","ee:ef:45:4f:f3:01","38:76:fc:c6:b4:11",2)
#print s.decode()
print hexdump(s.pack())
#s.socksendARP()
'''




