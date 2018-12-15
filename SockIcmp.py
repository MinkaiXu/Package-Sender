import os
import socket
import struct
from scapy.all import *
from PacketProcess import *
import SockPcap
import array

class sockICMP(object):
    def __init__(self, sip='127.0.0.1', dip='127.0.0.1', type = 8, code = 0, data=''):
        # self.timeout = 3
        self.ICMP_src           = sip
        self.ICMP_dst           = dip
        self.ICMP_type          = type      # 8bit
        self.ICMP_code          = code      # 8bit
        self.ICMP_data          = hexinput(data)
        self.ICMP_extrahead     = "s"       # 32bit or more
        self.ICMP_extraheadlen  = 4         # unit as bytes
        self.ehdefault()                    # default extra head

        # meaningless data for icmp

    # generate checksum
    def checksum(self,source):
        checksum = 0
        count = (len(source) / 2) * 2
        i = 0
        while i < count:
            temp = ord(source[i + 1]) * 256 + ord(source[i])  # 256 = 2^8
            checksum = checksum + temp
            checksum = checksum & 0xffffffff  # 4,294,967,296 (2^32)
            i = i + 2
        if i < len(source):
            checksum = checksum + ord(source[len(source) - 1])
            checksum = checksum & 0xffffffff
        # 32-bit to 16-bit
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = checksum + (checksum >> 16)
        answer = ~checksum
        answer = answer & 0xffff
        return answer

    # extrahead generate with data
    def eh(self,data):
        self.ICMP_extrahead = hexinput(data)
        self.ICMP_extraheadlen = len(data) / 2

    # extrahead generate without data
    def ehdefault(self):
        if self.ICMP_type in [0,8]:
            self.ICMP_extrahead = struct.pack('HH',0x0001,0x0002)
            self.extralen = 4
        elif self.ICMP_type in [17,18]:
            self.ICMP_extrahead = struct.pack('LL',0x00010002,0x00ffffff)
            self.extralen = 8
        elif self.ICMP_type in [13,14]:
            self.ICMP_extrahead = struct.pack('LLLL',0x00010002,0x00000000,0x00000000,0x00000000)
            self.extralen = 16
        elif self.ICMP_type in [11, 5, 3, 4 ]:
            self.ICMP_extrahead = struct.pack('LL', 0x00000000, 0x00000040)
            self.extralen = 8
        else:
            self.ICMP_extrahead = b''
            self.extralen = 0

    # decode is used to demonstrate the ICMP packet
    def decode(self):
        self.pack()
        s = ""
        s = s + "Internet Control Message Protocol \n"
        s = s + "\t Type : " + str(self.ICMP_type) + "(" +  inttohex(self.ICMP_type,2) + ")\n"
        s = s + "\t Code : " + str(self.ICMP_code) + "(" + inttohex(self.ICMP_code, 2) + ")\n"
        s = s + "\t Checksum : " + inttohex(self.ICMP_cksum, 4)[2:4] + inttohex(self.ICMP_cksum, 4)[0:2] + "\n"
        s = s + "\t ICMP Optional Header : " + "\n\t "
        for i in range(len(self.ICMP_extrahead)):
            s = s + inttohex(ord(self.ICMP_extrahead[i]),2)
        s = s + "\n"
        s = s + "\t ICMP Data : " + "\n\t " + hexoutput(self.ICMP_data)
        return s

    # pack is used to generate the whole packet (sendp in automatic Ethernet & IP head)
    def pack(self):
        header = struct.pack('bbH',self.ICMP_type,self.ICMP_code,0) #head struct
        packet = header + self.ICMP_extrahead + self.ICMP_data
        self.ICMP_cksum = self.checksum(packet)
        header = struct.pack('bbH',self.ICMP_type,self.ICMP_code,self.ICMP_cksum) #head with checksum
        return header + self.ICMP_extrahead + self.ICMP_data  # packet: head + data
        #os.getpid()

    # socksendICMP is used to send to ICMP packet
    def sendsockICMP(self):
        ICMPsender = IP(dst=self.ICMP_dst, src=self.ICMP_src, proto=1) / self.pack()
        #hexdump(ICMPsender)
        send(ICMPsender)

    # appendPCAP is used to write the packet into a file
    def appendPCAP(self,filename):
        tmp = Ether(type=0x0800) / IP(dst=self.ICMP_dst, src=self.ICMP_src, proto=1) / self.pack()
        SockPcap.PCAPwrite(filename,tmp)

'''
s3 = sockICMP('192.168.1.102','6.7.8.9',8,0,'7746869736973666F7269636D707465734')
s3.ICMP_dst = "10.11.12.13"
s4 = sockICMP('192.168.1.102','6.7.8.9',17,0)
s5 = sockICMP('192.168.1.102','6.7.8.9',11,0)
s3.eh("01000300")
#s3.sendsockICMP()
#s4.sendsockICMP()
#s5.sendsockICMP()
print s3.decode()
print hexdump(s3.pack())
print s4.decode()
print hexdump(s4.pack())
print s5.decode()
print hexdump(s5.pack())
'''