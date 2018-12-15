import socket
import struct
import SockIp
from scapy.all import *
from PacketProcess import *
import SockPcap
class sockTCP(object):
    def __init__(self, sip='127.0.0.1', spt=14006, dip='127.0.0.1', dpt=8080, data='', opt=''):
        self.TCP_SrcPort    = spt                           # 16bit
        self.TCP_DstPort    = dpt                           # 16bit
        self.TCP_SeqNum     = 0x21763e4f                    # 32bit
        self.TCP_AckNum     = 0x8b39b7c1                    # 32bit
        self.TCP_Offset     = 5                             #  4bit
        self.TCP_Reserve    = 0                             #  4bit
        self.TCP_CWR        = 0                             #  1bit
        self.TCP_ECE        = 0                             #  1bit
        self.TCP_URG        = 0                             #  1bit
        self.TCP_ACK        = 0                             #  1bit
        self.TCP_PSH        = 0                             #  1bit
        self.TCP_RST        = 0                             #  1bit
        self.TCP_SYN        = 1                             #  1bit
        self.TCP_FIN        = 0                             #  1bit
        self.TCP_Window     = 65523                         # 16bit
        self.TCP_CheckSum   = 0                             # 16bit
        self.TCP_Urgent     = 0                             # 16bit
        self.TCP_Option     = hexinput(opt)
        self.TCP_Data       = hexinput(data)
        self.IP_Header      = SockIp.sockIP(sip, dip, "", socket.IPPROTO_TCP)
        self.IP_src         = sip
        self.IP_dst         = dip

    # decode is used to demonstrate the TCP packet
    def decode(self):
        self.pack()
        s = ""
        s = s + "Transmission Control Protocol, Src Port : " + str(self.TCP_SrcPort) + " , Dst Port : " + str(self.TCP_DstPort)
        s = s + ", Seq : " + str(self.TCP_SeqNum) + " , Ack : " + str(self.TCP_AckNum) + "\n"
        s = s + "\t Source Port : " + str(self.TCP_SrcPort) + "(" + inttohex(self.TCP_SrcPort, 4) + ")\n"
        s = s + "\t Destination Port : " + str(self.TCP_DstPort) + "(" + inttohex(self.TCP_DstPort, 4) + ")\n"
        s = s + "\t Sequence Number : " + str(self.TCP_SeqNum) + "(" + inttohex(int(self.TCP_SeqNum), 8)[0:8] + ")\n"
        s = s + "\t Acknowledge Number : " + str(self.TCP_AckNum) + "(" + inttohex(int(self.TCP_AckNum), 8)[0:8] + ")\n"
        s = s + "\t Header Length : " + str(self.TCP_Offset/4) + "(" + inttohex(self.TCP_Offset/16, 1) \
            + ") " + str(self.TCP_Offset /4) + " Bytes\n"
        s = s + "\t Flag: " + inttohex(self.TCP_Flags, 3)
        flaglist = [self.TCP_CWR,self.TCP_ECE,self.TCP_URG,self.TCP_ACK,self.TCP_PSH,self.TCP_RST,self.TCP_SYN,self.TCP_FIN]
        flagtag = ["[CWR]","[ECE]","[URG]","[ACK]","[PSH]","[RST]","[SYN]","[FIN]"]
        for i in range(8):
            if (flaglist[i]):
                s = s + " " + flagtag[i]
        s = s + "\n\t Window Size Value : " + str(self.TCP_Window) + "(" + inttohex(self.TCP_Window, 4) + ")\n"
        s = s + "\t Checksum : " + inttohex(self.TCP_CheckSum, 4)[2:4] + inttohex(self.TCP_CheckSum, 4)[0:2] + "\n"
        s = s + "\t Urgent pointer: " + str(self.TCP_Urgent) + "(" + inttohex(self.TCP_Urgent, 4) + ")\n"
        s = s + "\t TCP Optional Header : " + "\n\t " + hexoutput(self.TCP_Option) + "\n"
        s = s + "\t TCPData : " + "\n\t " + hexoutput(self.TCP_Data)
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

    # pack is used to generate the whole packet (sendp in automatic Ethernet & IP head)
    def pack(self):
        TCPHeaderLen        = 20
        self.TCP_Length     = TCPHeaderLen + len(self.TCP_Option) + len(self.TCP_Data)
        self.TCP_Offset = (int((TCPHeaderLen + len(self.TCP_Option)) / 4) << 4 | 0) & 0xff
        self.TCP_Flags      = (self.TCP_CWR<<7) + (self.TCP_ECE<<6) + (self.TCP_URG<<5) + (self.TCP_ACK<<4) +\
                              (self.TCP_PSH<<3) + (self.TCP_RST<<2) + (self.TCP_SYN<<1) + self.TCP_FIN
        Header              = struct.pack("!4s4sBBHHHLLBBHHH",
                                          self.IP_Header.IP_Src,
                                          self.IP_Header.IP_Dst,
                                          0,
                                          self.IP_Header.IP_Protocol,
                                          self.TCP_Length,
                                          self.TCP_SrcPort,
                                          self.TCP_DstPort,
                                          self.TCP_SeqNum,
                                          self.TCP_AckNum,
                                          self.TCP_Offset,
                                          self.TCP_Flags,
                                          self.TCP_Window,
                                          0,
                                          self.TCP_Urgent)
        self.TCP_CheckSum   = self.checksum( Header + self.TCP_Option + self.TCP_Data )
        self.TCP_Header     = Header[12:28] + struct.pack("H", self.TCP_CheckSum) + Header[30:]
        self.TCP_HandD      = self.TCP_Header + self.TCP_Option + self.TCP_Data
        return self.TCP_HandD

    # socksendTCP is used to send to TCP packet
    def sendsockTCP(self):
        TCPsender = IP(dst=self.IP_dst, src=self.IP_src, proto=6) / self.pack()
        #print hexdump(TCPsender)
        send(TCPsender)

    # appendPCAP is used to write the packet into a file
    def appendPCAP(self,filename):
        tmp = Ether(type=0x0800) / IP(dst=self.IP_dst, src=self.IP_src, proto=6) / self.pack()
        SockPcap.PCAPwrite(filename,tmp)

'''
s = sockTCP('192.168.1.102', 14006, '6.7.8.9', 50007, '746869736973666F727463707061636B657474657374','34b56b2f')
print s.decode()
print hexdump(s.pack())
s.sendsockTCP()
'''


