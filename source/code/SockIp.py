import os
import socket
import struct
from PacketProcess import *
from scapy.all import *
import SockPcap
import array
import random


class sockIP(object):
    def __init__(self, src='127.0.0.1', dst='127.0.0.1', data='', proto=socket.IPPROTO_TCP, opt=''):
        self.IP_Version = 4
        self.IP_HeadLen = 20 + len(opt) / 2
        self.IP_SvcType = 0
        self.IP_TotalLen = self.IP_HeadLen + len(hexinput(data))
        self.IP_Identify = 0x0001
        self.IP_DF = 0
        self.IP_MF = 0
        self.IP_FgOffset = 0
        self.IP_TTL = 64
        self.IP_Protocol = proto
        self.IP_CheckSum = 0
        self.IP_Src = socket.inet_aton(src)
        self.IP_Dst = socket.inet_aton(dst)
        self.IP_Option = hexinput(opt)
        self.IP_Data = hexinput(data)
        self.IP_SrcOri = src
        self.IP_DstOri = dst

    def decode(self):
        self.pack()
        s = ""
        s = s + "Internet Protocol " + str(self.IP_Version) + ", Src : " + \
            self.IP_SrcOri + " , Dst : " + self.IP_DstOri + "\n"
        s = s + "\t Protocol Version : " + \
            str(self.IP_Version) + "(" + inttohex(self.IP_Version, 1) + ")\n"
        s = s + "\t Header Length : " + \
            str(self.IP_HeadLen) + "(" + inttohex(self.IP_HeadLen/4, 1) + ")\n"
        s = s + "\t Differentiated Services Field : " + \
            str(self.IP_SvcType) + "(" + inttohex(self.IP_SvcType, 2) + ")\n"
        s = s + "\t Total Length : " + \
            str(self.IP_TotalLen) + "(" + inttohex(self.IP_TotalLen, 4) + ")\n"
        s = s + "\t Identification : " + \
            str(int(self.IP_Identify)) + \
            "(" + inttohex(int(self.IP_Identify), 4) + ")\n"
        s = s + "\t Flag :" + \
            inttohex((self.IP_DF << 2) + (self.IP_MF << 1), 1) + \
            "  ..0.... Reserved bit \n"
        s = s + "\t\t..." + str(self.IP_DF) + "... Don't Fragment \n"
        s = s + "\t\t...." + str(self.IP_MF) + ".. More Fragments \n"
        s = s + "\t Fragment Offset : " + str(self.IP_FgOffset) + "(" \
            + inttohex((self.IP_DF << 14) + (self.IP_MF << 13) +
                       self.IP_FgOffset/8, 4) + ")\n"
        s = s + "\t Time to Live : " + \
            str(self.IP_TTL) + "(" + inttohex(self.IP_TTL, 2) + ")\n"
        s = s + "\t Protocol : " + \
            str(self.IP_Protocol) + "(" + inttohex(self.IP_Protocol, 2) + ")\n"
        s = s + "\t Checksum : " + \
            inttohex(self.IP_CheckSum, 4)[
                2:4] + inttohex(self.IP_CheckSum, 4)[0:2] + "\n"
        s = s + "\t Source : " + self.IP_SrcOri + \
            "(" + addresstohex(self.IP_SrcOri) + ")\n"
        s = s + "\t Destination : " + self.IP_DstOri + \
            "(" + addresstohex(self.IP_DstOri) + ")\n"
        s = s + "\t IP Optional Header : " + \
            "\n\t " + hexoutput(self.IP_Option) + "\n"
        s = s + "\t IPData : " + "\n\t " + hexoutput(self.IP_Data)
        return s

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

    def pack(self):
        Header = struct.pack("!BBHHHBBH4s4s",
                             (self.IP_Version << 4 | int(self.IP_HeadLen / 4)),
                             self.IP_SvcType,
                             self.IP_TotalLen,
                             self.IP_Identify,
                             ((self.IP_DF << 14) +
                              (self.IP_MF << 13) + self.IP_FgOffset),
                             self.IP_TTL,
                             self.IP_Protocol,
                             0,
                             self.IP_Src,
                             self.IP_Dst)

        self.IP_CheckSum = self.checksum(Header+self.IP_Option)
        self.IP_Header = Header[:10] + \
            struct.pack("H", self.IP_CheckSum) + Header[12:]
        self.IP_HandD = self.IP_Header + self.IP_Option + self.IP_Data
        return self.IP_HandD

    def sendsockIP(self):
        IPsender = IP(self.pack())
        send(IPsender)

    def appendPCAP(self, filename):
        tmp = Ether(type=0x0800) / self.pack()
        SockPcap.PCAPwrite(filename, tmp)
