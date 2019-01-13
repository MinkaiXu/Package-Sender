import Sniffer
from PacketProcess import *


def filterDstIP(packetls, dstip):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        # ARP(1)
        if Sniffer.decideProtol(packetls[i]) == 1 and packetls[i].payload.pdst == dstip:
            feedback.append(i)
        # IP(2)
        elif Sniffer.decideProtol(packetls[i]) == 2 and packetls[i].payload.dst == dstip:
            feedback.append(i)
        # ICMP(3):
        elif Sniffer.decideProtol(packetls[i]) == 3 and packetls[i].payload.dst == dstip:
            feedback.append(i)
        # TCP(4):
        elif Sniffer.decideProtol(packetls[i]) == 4 and packetls[i].payload.dst == dstip:
            feedback.append(i)
        # UDP(5):
        elif Sniffer.decideProtol(packetls[i]) == 5 and packetls[i].payload.dst == dstip:
            feedback.append(i)
    return feedback


def filterSrcIP(packetls, srcip):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        # ARP(1)
        if Sniffer.decideProtol(packetls[i]) == 1 and packetls[i].payload.psrc == srcip:
            feedback.append(i)
        # IP(2)
        elif Sniffer.decideProtol(packetls[i]) == 2 and packetls[i].payload.src == srcip:
            feedback.append(i)
        # ICMP(3):
        elif Sniffer.decideProtol(packetls[i]) == 3 and packetls[i].payload.src == srcip:
            feedback.append(i)
        # TCP(4):
        elif Sniffer.decideProtol(packetls[i]) == 4 and packetls[i].payload.src == srcip:
            feedback.append(i)
        # UDP(5):
        elif Sniffer.decideProtol(packetls[i]) == 5 and packetls[i].payload.src == srcip:
            feedback.append(i)
    return feedback


def filterSrcPort(packetls, srcport):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        # TCP(4):
        if Sniffer.decideProtol(packetls[i]) == 4 and packetls[i].payload.payload.sport == srcport:
            feedback.append(i)
        # UDP(5):
        elif Sniffer.decideProtol(packetls[i]) == 5 and packetls[i].payload.payload.sport == srcport:
            feedback.append(i)
    return feedback


def filterDstPort(packetls, dstport):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        # TCP(4):
        if Sniffer.decideProtol(packetls[i]) == 4 and packetls[i].payload.payload.dport == dstport:
            feedback.append(i)
        # UDP(5):
        elif Sniffer.decideProtol(packetls[i]) == 5 and packetls[i].payload.payload.dport == dstport:
            feedback.append(i)
    return feedback


def filterARP(packetls):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 1:  # arp(1):
            feedback.append(i)
    return feedback


def filterIP(packetls):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 2:  # ip(2):
            feedback.append(i)
    return feedback


def filterICMP(packetls):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 3:  # icmp(3):
            feedback.append(i)
    return feedback


def filterTCP(packetls):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 4:  # tcp(4):
            feedback.append(i)
    return feedback


def filterUDP(packetls):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 5:  # udp(5):
            feedback.append(i)
    return feedback


def filterData(packetls, target):
    feedback = []
    # arp  1, ip  2, icmp  3, tcp  4, udp  5
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 2 and \
                target in hexoutput(str(packetls[i].payload.payload)):  # IP(2)
            feedback.append(i)
        elif Sniffer.decideProtol(packetls[i]) == 3 and \
                target in hexoutput(str(packetls[i].payload.payload.payload)):  # ICMP(3):
            feedback.append(i)
        elif Sniffer.decideProtol(packetls[i]) == 4 and \
                target in hexoutput(str(packetls[i].payload.payload.payload)):  # TCP(4):
            feedback.append(i)
        elif Sniffer.decideProtol(packetls[i]) == 5 and \
                target in hexoutput(str(packetls[i].payload.payload.payload)):  # UDP(5):
            feedback.append(i)
    return feedback


'''
    ScanPackets return a brief description list of Scanned packets
'''


def ScanPackets(packetls):
    feedback = []
    for i in range(len(packetls)):
        if Sniffer.decideProtol(packetls[i]) == 1:  # ARP(1)
            tmp = ''
            tmp += str(packetls[i].time) + "  ARP  "
            if (packetls[i].payload.op == 1):
                tmp += "(Request) "
                tmp += "Who has " + \
                    packetls[i].payload.pdst + "? Tell " + \
                    packetls[i].payload.psrc
            elif (packetls[i].payload.op == 2):
                tmp += "(Reply) "
                tmp += packetls[i].payload.psrc + \
                    " is at " + packetls[i].payload.hwsrc
            else:
                pass
            feedback.append(tmp)
        elif Sniffer.decideProtol(packetls[i]) == 2:  # IP(2)
            tmp = ''
            tmp += str(packetls[i].time) + "  IPv"
            tmp += str(packetls[i].payload.version) + ", Src : " + \
                packetls[i].payload.src + " , Dst : " + packetls[i].payload.dst
            feedback.append(tmp)
        elif Sniffer.decideProtol(packetls[i]) == 3:  # ICMP(3):
            tmp = ''
            tmp += str(packetls[i].time) + "  ICMP, type:"
            tmp += str(packetls[i].payload.payload.type) + \
                ", Src : " + packetls[i].payload.src + \
                " , Dst : " + packetls[i].payload.dst
            feedback.append(tmp)
        elif Sniffer.decideProtol(packetls[i]) == 4:  # TCP(4):
            tmp = ''
            tmp += str(packetls[i].time)
            tmp += "  TCP, Src Port : " + str(packetls[i].payload.payload.sport) + \
                   " , Dst Port : " + str(packetls[i].payload.payload.dport)
            feedback.append(tmp)
        elif Sniffer.decideProtol(packetls[i]) == 5:  # UDP(5):
            tmp = ''
            tmp += str(packetls[i].time)
            tmp += "  UDP, Src Port : " + str(packetls[i].payload.payload.sport) + \
                   " , Dst Port : " + str(packetls[i].payload.payload.dport)
            feedback.append(tmp)
        else:
            feedback.append("Other Protocols")
    return feedback
