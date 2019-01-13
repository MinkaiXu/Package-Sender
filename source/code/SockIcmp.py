import os
import socket
import struct
from scapy.all import *
from PacketProcess import *
import SockPcap
import array


class sockICMP(object):
    def __init__(self, sip='127.0.0.1', dip='127.0.0.1', type=8, code=0, data=''):
        self.ICMP_src = sip
        self.ICMP_dst = dip
        self.ICMP_type = type
        self.ICMP_code = code
        self.ICMP_data = hexinput(data)
        self.ICMP_extrahead = "s"
        self.ICMP_extraheadlen = 4
        self.ehdefault()

    def checksum(self, source):
        checksum = 0
        count = (len(source) / 2) * 2
        i = 0
        while i < count:
            temp = ord(source[i + 1]) * 256 + ord(source[i])
            checksum = checksum + temp
            checksum = checksum & 0xffffffff
            i = i + 2
        if i < len(source):
            checksum = checksum + ord(source[len(source) - 1])
            checksum = checksum & 0xffffffff
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = checksum + (checksum >> 16)
        answer = ~checksum
        answer = answer & 0xffff
        return answer

    def eh(self, data):
        self.ICMP_extrahead = hexinput(data)
        self.ICMP_extraheadlen = len(data) / 2

    def ehdefault(self):
        if self.ICMP_type in [0, 8]:
            self.ICMP_extrahead = struct.pack('HH', 0x0001, 0x0002)
            self.extralen = 4
        elif self.ICMP_type in [17, 18]:
            self.ICMP_extrahead = struct.pack('LL', 0x00010002, 0x00ffffff)
            self.extralen = 8
        elif self.ICMP_type in [13, 14]:
            self.ICMP_extrahead = struct.pack(
                'LLLL', 0x00010002, 0x00000000, 0x00000000, 0x00000000)
            self.extralen = 16
        elif self.ICMP_type in [11, 5, 3, 4]:
            self.ICMP_extrahead = struct.pack('LL', 0x00000000, 0x00000040)
            self.extralen = 8
        else:
            self.ICMP_extrahead = b''
            self.extralen = 0

    def decode(self):
        self.pack()
        s = ""
        s = s + "Internet Control Message Protocol \n"
        s = s + "\t Type : " + str(self.ICMP_type) + \
            "(" + inttohex(self.ICMP_type, 2) + ")\n"
        s = s + "\t Code : " + str(self.ICMP_code) + \
            "(" + inttohex(self.ICMP_code, 2) + ")\n"
        s = s + "\t Checksum : " + \
            inttohex(self.ICMP_cksum, 4)[2:4] + \
            inttohex(self.ICMP_cksum, 4)[0:2] + "\n"
        s = s + "\t ICMP Optional Header : " + "\n\t "
        for i in range(len(self.ICMP_extrahead)):
            s = s + inttohex(ord(self.ICMP_extrahead[i]), 2)
        s = s + "\n"
        s = s + "\t ICMP Data : " + "\n\t " + hexoutput(self.ICMP_data)
        return s

    def pack(self):
        header = struct.pack('bbH', self.ICMP_type, self.ICMP_code, 0)
        packet = header + self.ICMP_extrahead + self.ICMP_data
        self.ICMP_cksum = self.checksum(packet)
        header = struct.pack('bbH', self.ICMP_type,
                             self.ICMP_code, self.ICMP_cksum)
        return header + self.ICMP_extrahead + self.ICMP_data

    def sendsockICMP(self):
        ICMPsender = IP(dst=self.ICMP_dst, src=self.ICMP_src,
                        proto=1) / self.pack()

        send(ICMPsender)

    def appendPCAP(self, filename):
        tmp = Ether(type=0x0800) / IP(dst=self.ICMP_dst,
                                      src=self.ICMP_src, proto=1) / self.pack()
        SockPcap.PCAPwrite(filename, tmp)
