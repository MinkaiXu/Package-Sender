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
        self.IP_Version     = 4                                         #  4bit
        self.IP_HeadLen     = 20 + len(opt) / 2                         #  4bit
        self.IP_SvcType     = 0 # Type of Service                       #  8bit
        self.IP_TotalLen    = self.IP_HeadLen + len( hexinput(data) )   # 16bit
        self.IP_Identify    = 0x0001                                    # 16bit
        self.IP_DF          = 0                                         #  1bit
        self.IP_MF          = 0                                         #  1bit
        self.IP_FgOffset    = 0                                         # 13bit
        self.IP_TTL         = 64                                        #  8bit
        self.IP_Protocol    = proto                                     #  8bit
        self.IP_CheckSum    = 0 # will be filled by kernel              # 16bit
        self.IP_Src         = socket.inet_aton( src )                   # 32bit
        self.IP_Dst         = socket.inet_aton( dst )                   # 32bit
        self.IP_Option      = hexinput(opt)
        self.IP_Data        = hexinput(data)
        self.IP_SrcOri      = src
        self.IP_DstOri      = dst

    # decode is used to demonstrate the IP packet
    def decode(self):
        self.pack()
        s = ""
        s = s + "Internet Protocol " + str(self.IP_Version) + ", Src : " + \
            self.IP_SrcOri + " , Dst : " + self.IP_DstOri + "\n"
        s = s + "\t Protocol Version : " + str(self.IP_Version) + "(" + inttohex(self.IP_Version, 1) + ")\n"
        s = s + "\t Header Length : " + str(self.IP_HeadLen) + "(" + inttohex(self.IP_HeadLen/4, 1) + ")\n"
        s = s + "\t Differentiated Services Field : " + str(self.IP_SvcType) + "(" + inttohex(self.IP_SvcType, 2) + ")\n"
        s = s + "\t Total Length : " + str(self.IP_TotalLen) + "(" + inttohex(self.IP_TotalLen, 4) + ")\n"
        s = s + "\t Identification : " + str(int(self.IP_Identify)) + "(" + inttohex(int(self.IP_Identify), 4) + ")\n"
        s = s + "\t Flag :" + inttohex((self.IP_DF << 2) + (self.IP_MF << 1) , 1) + "  ..0.... Reserved bit \n"
        s = s + "\t\t..." + str(self.IP_DF) + "... Don't Fragment \n"
        s = s + "\t\t...." + str(self.IP_MF) + ".. More Fragments \n"
        s = s + "\t Fragment Offset : " + str(self.IP_FgOffset) + "(" \
            + inttohex((self.IP_DF << 14) + (self.IP_MF << 13) + self.IP_FgOffset/8, 4) + ")\n"
        s = s + "\t Time to Live : " + str(self.IP_TTL) + "(" + inttohex(self.IP_TTL, 2) + ")\n"
        s = s + "\t Protocol : " + str(self.IP_Protocol) + "(" + inttohex(self.IP_Protocol, 2) + ")\n"
        s = s + "\t Checksum : " + inttohex(self.IP_CheckSum, 4)[2:4] + inttohex(self.IP_CheckSum, 4)[0:2] + "\n"
        s = s + "\t Source : " + self.IP_SrcOri + "(" + addresstohex(self.IP_SrcOri) + ")\n"
        s = s + "\t Destination : " + self.IP_DstOri + "(" + addresstohex(self.IP_DstOri) + ")\n"
        s = s + "\t IP Optional Header : " + "\n\t " + hexoutput(self.IP_Option) + "\n"
        s = s + "\t IPData : " + "\n\t " + hexoutput(self.IP_Data)
        return s

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

    # pack is used to generate the whole packet (sendp in automatic Ethernet head)
    def pack(self):
        Header = struct.pack("!BBHHHBBH4s4s",
                         (self.IP_Version << 4 | int(self.IP_HeadLen / 4)),
                         self.IP_SvcType,
                         self.IP_TotalLen,
                         self.IP_Identify,
                         ((self.IP_DF << 14) + (self.IP_MF << 13) + self.IP_FgOffset),
                         self.IP_TTL,
                         self.IP_Protocol,
                         0,
                         self.IP_Src,
                         self.IP_Dst)
        #print type(self.IP_Option)
        #print type(Header)
        self.IP_CheckSum = self.checksum(Header+self.IP_Option)
        self.IP_Header = Header[:10] + struct.pack("H", self.IP_CheckSum) + Header[12:]
        self.IP_HandD = self.IP_Header + self.IP_Option + self.IP_Data
        return self.IP_HandD

    # socksendIP is used to send to IP packet
    def sendsockIP(self):
        IPsender = IP(self.pack())
        #print hexdump(IPsender)
        send(IPsender)

    # appendPCAP is used to write the packet into a file
    def appendPCAP(self,filename):
        tmp = Ether(type=0x0800) / self.pack()
        SockPcap.PCAPwrite(filename,tmp)

'''
s=sockIP('192.168.1.102','6.7.8.9','746869736973666F72697074657374',socket.IPPROTO_RAW, '34b56b2f8d7d9099')
print s.decode()
hexdump(s.pack())
#s.sendsockIP()
'''

