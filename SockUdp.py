import socket
import struct
import SockIp
from PacketProcess import *
from scapy.all import *
import SockPcap


class sockUDP(object):
    def __init__(self, sip='127.0.0.1', spt=14005, dip='127.0.0.1', dpt=8080, data=''):
        self.UDP_Data = hexinput(data)
        self.UDP_SrcPort = spt
        self.UDP_DstPort = dpt
        self.UDP_Length = 8 + len(self.UDP_Data)
        self.UDP_CheckSum = 0
        self.IP_Header = SockIp.sockIP(sip, dip, "", socket.IPPROTO_UDP)
        self.IP_src = sip
        self.IP_dst = dip

    def decode(self):
        self.pack()
        s = ""
        s = s + "User Data Protocol, Src Port : " + \
            str(self.UDP_SrcPort) + " , Dst Port : " + \
            str(self.UDP_DstPort) + "\n"
        s = s + "\t Source Port : " + \
            str(self.UDP_SrcPort) + "(" + inttohex(self.UDP_SrcPort, 4) + ")\n"
        s = s + "\t Destination Port : " + \
            str(self.UDP_DstPort) + "(" + inttohex(self.UDP_DstPort, 4) + ")\n"
        s = s + "\t Length : " + \
            str(self.UDP_Length) + "(" + inttohex(self.UDP_Length, 4) + ")\n"
        s = s + "\t Checksum : " + \
            inttohex(self.UDP_CheckSum, 4)[
                2:4] + inttohex(self.UDP_CheckSum, 4)[0:2] + "\n"
        s = s + "\t UDPData : " + "\n\t " + hexoutput(self.UDP_Data)
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
        Header = struct.pack('!4s4sBBHHHHH',
                             self.IP_Header.IP_Src,
                             self.IP_Header.IP_Dst,
                             0,
                             self.IP_Header.IP_Protocol,
                             self.UDP_Length,
                             self.UDP_SrcPort,
                             self.UDP_DstPort,
                             self.UDP_Length,
                             0)
        self.UDP_CheckSum = self.checksum(Header + self.UDP_Data)
        self.UDP_Header = Header[12:18] + \
            struct.pack("H", self.UDP_CheckSum) + Header[20:]
        self.UDP_HandD = self.UDP_Header + self.UDP_Data
        return self.UDP_HandD

    def sendsockUDP(self):
        UDPsender = IP(dst=self.IP_dst, src=self.IP_src,
                       proto=17) / self.pack()
        send(UDPsender)

    def appendPCAP(self, filename):
        tmp = Ether(type=0x0800) / IP(dst=self.IP_dst,
                                      src=self.IP_src, proto=17) / self.pack()
        SockPcap.PCAPwrite(filename, tmp)
