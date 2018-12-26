import SockArp
import SockIcmp
import SockIp
import PacketProcess
import PCAPfilter
import SockUdp
import Sniffer
import SockTcp
import cPickle
import zlib
import gzip
from scapy.utils import PcapReader, PcapWriter
from scapy.arch.pcapdnet import *
from scapy.arch import pcapdnet
from scapy.all import *
from scapy.sendrecv import debug, srp1
from scapy.layers.l2 import Ether, ARP
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

conf.use_pcap = 1
conf.use_dnet = 1

LOOPBACK_NAME = "lo0"
WINDOWS = True


class PicklablePacket:
    def __init__(self, pkt):
        self.contents = str(pkt)
        self.time = pkt.time

    def __call__(self):
        pkt = scapy.layers.l2.Ether(self.contents)
        pkt.time = self.time
        return pkt

    def dumps(self):
        return gzip.zlib.compress(cPickle.dumps(self)).encode('base64')

    @staticmethod
    def loads(string):
        p = cPickle.loads(gzip.zlib.decompress(string.decode('base64')))
        return p()


def PCAPread(file_name, start, count):
    reader = PcapReader(file_name)
    if start > 0:
        reader.read_all(start)
    if count > 0:
        return reader.read_all(count)
    else:
        return reader.read_all(-1)


def PCAPwrite(file_name, packets):
    writer = PcapWriter(file_name, append=True)
    for p in packets:
        writer.write(p)
    writer.flush()
    writer.close()


if __name__ == '__main__':

    s = SockTcp.sockTCP('192.168.1.102', 14006, '6.7.8.9', 50007,
                        '746869736973666F727463707061636B6574746573', '34b56b2f')
    s.TCP_CWR = 1
    s.TCP_ECE = 1
    s.TCP_Window = 6558
    s.TCP_FIN = 1
    s.TCP_RST = 1
    s2 = SockUdp.sockUDP('192.168.1.102', 14005, '6.7.8.9',
                         8080, '746869736973666F727564707061636B657474657374')
    s3 = SockIp.sockIP('192.168.1.102', '6.7.8.9',
                       '746869736973666F72697074657374', socket.IPPROTO_RAW, '34b56b2f8d7d9099')
    s4 = SockArp.sockARP("6.7.8.9", "192.168.1.102",
                         "ee:ef:45:4f:f3:01", "38:76:fc:c6:b4:11", 2)
    s5 = SockIcmp.sockICMP('192.168.1.102', '6.7.8.9', 8,
                           0, '746869736973666F7269636D7074657374')
    fn = "pcaps/new1.pcap"
    s.appendPCAP(fn)
    s.TCP_Offset = 66
    s.TCP_CWR = 0
    s.TCP_AckNum = 1235
    s = SockTcp.sockTCP('192.168.1.102', 14006, '6.7.8.9', 50007, '746869736973666F727463707061636B65747465',
                        '34b56b2f')
    s.appendPCAP(fn)
