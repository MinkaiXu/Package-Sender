from scapy.all import *
import SockArp,SockIcmp,SockUdp,SockTcp,SockPcap,SockIp,socket

'''
    decide the upper protocol
    return: arp 1, ip 2, icmp 3, tcp 4, udp 5 
'''
def decideProtol(packet):
    if packet.type == 0x0806:
        return 1
    elif packet.type == 0x0800 and packet.payload.proto == 1:
        return 3
    elif packet.type == 0x0800 and packet.payload.proto == 6:
        return 4
    elif packet.type == 0x0800 and packet.payload.proto == 17:
        return 5
    elif packet.type == 0x0800:
        return 2
    else:
        return 0

'''
    this function can return the new class of five protocols
'''

def new(packet):
    packType = decideProtol(packet)
    if packType == 1:
        return newARP(packet)
    elif packType == 2:
        return newIP(packet)
    elif packType == 3:
        return newICMP(packet)
    elif packType == 4:
        return newTCP(packet)
    elif packType == 5:
        return newUDP(packet)
    else:
        return 0


'''
    newARP can return the new class of ARP
'''
def newARP(packet):
    feedback = SockArp.sockARP()
    feedback.ARP_HardType = packet.payload.hwtype
    feedback.ARP_ProtoType = packet.payload.ptype
    feedback.ARP_HardSize = packet.payload.hwlen
    feedback.ARP_ProtoSize = packet.payload.plen
    feedback.ARP_OPcode = packet.payload.op
    feedback.ARP_SrcMac = packet.payload.hwsrc
    feedback.ARP_SrcIP = packet.payload.psrc
    feedback.ARP_DstMac = packet.payload.hwdst
    feedback.ARP_DstIP = packet.payload.pdst
    return feedback


'''
    newIP can return the new class of IP
'''
def newIP(packet):
    feedback = SockIp.sockIP()
    feedback.IP_Version = packet.payload.version
    feedback.IP_HeadLen = packet.payload.ihl * 4
    feedback.IP_SvcType = packet.payload.tos
    feedback.IP_TotalLen = packet.payload.len
    feedback.IP_Identify = packet.payload.id
    if (packet.payload.flags == 1):
        feedback.IP_DF = 0
        feedback.IP_MF = 1
    elif (packet.payload.flags == 2):
        feedback.IP_DF = 1
        feedback.IP_MF = 0
    elif (packet.payload.flags == 3):
        feedback.IP_DF = 1
        feedback.IP_MF = 1
    else:
        feedback.IP_DF = 0
        feedback.IP_MF = 0
    feedback.IP_FgOffset = packet.payload.frag
    feedback.IP_TTL = packet.payload.ttl
    feedback.IP_Protocol = packet.payload.proto
    feedback.IP_CheckSum = packet.payload.chksum
    feedback.IP_SrcOri = packet.payload.src
    feedback.IP_DstOri = packet.payload.dst
    feedback.IP_Src = socket.inet_aton(feedback.IP_SrcOri)
    feedback.IP_Dst = socket.inet_aton(feedback.IP_DstOri)
    feedback.IP_Data = str(packet.payload.payload)
    feedback.IP_Option = str(packet.payload)[20:feedback.IP_HeadLen]
    return feedback


'''
   newICMP can return the new class of ICMP
'''
def newICMP(packet):
    feedback = SockIcmp.sockICMP()
    feedback.ICMP_src = packet.payload.src
    feedback.ICMP_dst = packet.payload.dst
    feedback.ICMP_type = packet.payload.payload.type
    feedback.ICMP_code = packet.payload.payload.code
    if feedback.ICMP_type in [0, 8]:
        feedback.extralen = 4
    elif feedback.ICMP_type in [17, 18, 11, 5, 3, 4]:
        feedback.extralen = 8
    elif feedback.ICMP_type in [13, 14]:
        feedback.extralen = 16
    else:
        feedback.extralen = 0
    feedback.ICMP_extrahead = str(packet.payload.payload)[4:4+feedback.extralen]
    feedback.ICMP_data = str(packet.payload.payload)[4 + feedback.extralen : ]
    return feedback


'''
    newTCP can return the new class of TCP
'''
def newTCP(packet):
    feedback = SockTcp.sockTCP()
    feedback.TCP_SrcPort = packet.payload.payload.sport
    feedback.TCP_DstPort = packet.payload.payload.dport
    feedback.TCP_SeqNum = packet.payload.payload.seq
    feedback.TCP_AckNum = packet.payload.payload.ack
    feedback.TCP_Offset = packet.payload.payload.dataofs
    feedback.TCP_Reserve = packet.payload.payload.reserved
    tmp = bin(ord(str(packet.payload.payload)[13]))
    tmp = (10-len(tmp))*"0" + tmp[2:]
    feedback.TCP_CWR = int(tmp[0])
    feedback.TCP_ECE = int(tmp[1])
    feedback.TCP_URG = int(tmp[2])
    feedback.TCP_ACK = int(tmp[3])
    feedback.TCP_PSH = int(tmp[4])
    feedback.TCP_RST = int(tmp[5])
    feedback.TCP_SYN = int(tmp[6])
    feedback.TCP_FIN = int(tmp[7])
    feedback.TCP_Window = packet.payload.payload.window
    feedback.TCP_CheckSum = packet.payload.payload.chksum
    feedback.TCP_Urgent = packet.payload.payload.urgptr
    feedback.TCP_Option = str(packet.payload.payload)[20:4*feedback.TCP_Offset]
    feedback.TCP_Data = str(packet.payload.payload)[4*feedback.TCP_Offset:]
    feedback.IP_src = packet.payload.src
    feedback.IP_dst = packet.payload.dst
    feedback.IP_Header = SockIp.sockIP(feedback.IP_src, feedback.IP_dst, "", socket.IPPROTO_TCP)
    return feedback


'''
    newUDP can return the new class of UDP
'''
def newUDP(packet):
    feedback = SockUdp.sockUDP()
    feedback.IP_src = packet.payload.src
    feedback.IP_dst = packet.payload.dst
    feedback.UDP_SrcPort = packet.payload.payload.sport
    feedback.UDP_DstPort = packet.payload.payload.dport
    feedback.UDP_Length = packet.payload.payload.len
    feedback.UDP_CheckSum = packet.payload.payload.chksum
    feedback.IP_Header = SockIp.sockIP(feedback.IP_src, feedback.IP_dst, "", socket.IPPROTO_UDP)
    feedback.UDP_Data = str(packet.payload.payload)[8:]
    return feedback








