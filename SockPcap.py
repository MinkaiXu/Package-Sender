from scapy.all import *
from scapy.sendrecv import debug, srp1
from scapy.layers.l2 import Ether, ARP
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

conf.use_pcap = 1
conf.use_dnet = 1
from scapy.arch import pcapdnet
from scapy.arch.pcapdnet import *

LOOPBACK_NAME="lo0"
WINDOWS = True
from scapy.utils import PcapReader, PcapWriter
import gzip, zlib, cPickle, PacketNewLife,PCAPfilter,PacketProcess
import SockTcp,SockUdp,SockIp,SockIcmp,SockArp

class PicklablePacket:
    '''
    A container for scapy packets that can be pickled
    (in contrast to scapy pakcets themselves)
    '''
    def __init__(self, pkt):
        self.contents = str(pkt)
        self.time = pkt.time

    def __call__(self):
        # Get the original scapy packet
        pkt = scapy.layers.l2.Ether(self.contents)
        pkt.time = self.time
        return pkt

    def dumps(self):
        # use cpickle to dump
        return gzip.zlib.compress(cPickle.dumps(self)).encode('base64')

    @staticmethod
    def loads(string):
        # load object from string
        p = cPickle.loads(gzip.zlib.decompress(string.decode('base64')))
        return p()

def PCAPread(file_name, start, count):
    # read packets from pcap according to the start packet number and total count
    reader = PcapReader(file_name)
    if start > 0:
        reader.read_all(start)
    if count > 0:
        return reader.read_all(count)
    else:
        return reader.read_all(-1)


def PCAPwrite(file_name, packets):
    # write packets into pcap, packets in a list of python
    writer = PcapWriter(file_name, append=True)
    for p in packets:
        writer.write(p)
    writer.flush()
    writer.close()


if __name__ == '__main__':
    '''packets = read('pcaps/new.pcap', 0, 10)
    # packle the packets to transfer
    p = PicklablePacket(packets[0])
    s = p.dumps()
    p = PicklablePacket.loads(s)
    print p
    print p.summary()
    '''

    '''
    serialized_packets = [PicklablePacket(p).dumps() for p in packets]
    deserialized_packets = [PicklablePacket.loads(s) for s in serialized_packets]
    write('pcaps/new2.pcap', packets)'''


    s = SockTcp.sockTCP('192.168.1.102', 14006, '6.7.8.9', 50007, '746869736973666F727463707061636B6574746573', '34b56b2f')
    s.TCP_CWR = 1
    s.TCP_ECE = 1
    s.TCP_Window = 6558
    s.TCP_FIN = 1
    s.TCP_RST = 1
    s2 = SockUdp.sockUDP('192.168.1.102', 14005, '6.7.8.9', 8080, '746869736973666F727564707061636B657474657374')
    s3 = SockIp.sockIP('192.168.1.102', '6.7.8.9', '746869736973666F72697074657374', socket.IPPROTO_RAW, '34b56b2f8d7d9099')
    s4 = SockArp.sockARP("6.7.8.9", "192.168.1.102", "ee:ef:45:4f:f3:01", "38:76:fc:c6:b4:11", 2)
    s5 = SockIcmp.sockICMP('192.168.1.102', '6.7.8.9', 8, 0, '746869736973666F7269636D7074657374')
    fn = "pcaps/new1.pcap"
    s.appendPCAP(fn)
    s.TCP_Offset = 66
    s.TCP_CWR = 0
    s.TCP_AckNum = 1235
    s = SockTcp.sockTCP('192.168.1.102', 14006, '6.7.8.9', 50007, '746869736973666F727463707061636B65747465',
                        '34b56b2f')
    s.appendPCAP(fn)
    #s2.appendPCAP(fn)
    #s3.appendPCAP(fn)
    #s4.appendPCAP(fn)
    #s5.appendPCAP(fn)


    '''
    b = PCAPread('pcaps/new.pcap',0,400)

    a = PCAPfilter.filterTCP(b)
    print a
    t = [b[i] for i in a]
    print PCAPfilter.ScanPackets(t)

    print PCAPfilter.filterIP(b)
    print PCAPfilter.filterICMP(b)
    print PCAPfilter.filterTCP(b)
    print PCAPfilter.filterUDP(b)
    print PCAPfilter.filterDstIP(b,'6.7.8.9')
    print PCAPfilter.filterDstPort(b,8080)
    print PCAPfilter.filterSrcIP(b,'6.7.8.9')
    print PCAPfilter.filterSrcPort(b,14006)
    print PCAPfilter.filterData(b,PacketProcess.hexoutput("cmp"))
    '''

    '''
    for i in range(len(b)):
        #print PacketNewLife.decideProtol(b[i])
        if PacketNewLife.decideProtol(b[i]) == 1:
            a = PacketNewLife.BringNewLifeARP(b[i])
            #print a.decode()
        elif PacketNewLife.decideProtol(b[i]) == 2:
            a = PacketNewLife.BringNewLifeIP(b[i])
            print a.decode()
        elif PacketNewLife.decideProtol(b[i]) == 3:
            a = PacketNewLife.BringNewLifeICMP(b[i])
            print a.decode()
        elif PacketNewLife.decideProtol(b[i]) == 4:
            a = PacketNewLife.BringNewLifeTCP(b[i])
            print a.decode()
        elif PacketNewLife.decideProtol(b[i]) == 5:
            a = PacketNewLife.BringNewLifeUDP(b[i])
            print a.decode()
    '''

    '''print type(b[3])
    print b[3].dst
    print b[3].src
    print b[3].proto
    tmp = b[3].payload
    print tmp.dport
    print tmp.sport'''
    #Ether(str(b[0])).show()


    #p10 = b[10]
    #print hexdump(p10)
    #b.nsummary()

    #send(b[1])

    '''
    a = read('pcaps/icmptest2.pcap',0,100)
    print a
    print type(a[31])
    print hexdump(a[31])
    b = Ether()/IP()
    print type(b)
    print hexdump(b)
    #send(a[31])
    '''
