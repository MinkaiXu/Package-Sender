# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'readprap.ui'
#
# Created by: PyQt5 UI code generator 5.7.1
#
# WARNING! All changes made in this file will be lost!

import PCAPfilter,SockPcap
from PacketNewLife import BringNewLife,decideProtol
from scapy.all import hexdump
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_readpcap(object):
    def setupUi(self, readpcap):
        readpcap.setObjectName("readpcap")
        readpcap.resize(920, 656)
        self.pcapdisplay = QtWidgets.QTextEdit(readpcap)
        self.pcapdisplay.setGeometry(QtCore.QRect(445, 20, 452, 571))
        self.pcapdisplay.setObjectName("pcapdisplay")
        self.pcapsend = QtWidgets.QPushButton(readpcap)
        self.pcapsend.setGeometry(QtCore.QRect(590, 600, 161, 41))
        self.pcapsend.setObjectName("pcapsend")
        self.label = QtWidgets.QLabel(readpcap)
        self.label.setGeometry(QtCore.QRect(10, 20, 51, 16))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.pcapfilename = QtWidgets.QLineEdit(readpcap)
        self.pcapfilename.setGeometry(QtCore.QRect(50, 20, 341, 21))
        self.pcapfilename.setObjectName("pcapfilename")
        self.pcapfilechoose = QtWidgets.QPushButton(readpcap)
        self.pcapfilechoose.setGeometry(QtCore.QRect(390, 20, 31, 21))
        self.pcapfilechoose.setObjectName("pcapfilechoose")
        self.label_2 = QtWidgets.QLabel(readpcap)
        self.label_2.setGeometry(QtCore.QRect(10, 50, 61, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.pcapdisplaydigest = QtWidgets.QTextEdit(readpcap)
        self.pcapdisplaydigest.setGeometry(QtCore.QRect(20, 300, 401, 291))
        self.pcapdisplaydigest.setObjectName("pcapdisplaydigest")
        self.label_3 = QtWidgets.QLabel(readpcap)
        self.label_3.setGeometry(QtCore.QRect(20, 610, 271, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.pcapseqnum = QtWidgets.QLineEdit(readpcap)
        self.pcapseqnum.setGeometry(QtCore.QRect(292, 610, 91, 31))
        self.pcapseqnum.setObjectName("pcapseqnum")
        self.pcaptodisplay = QtWidgets.QPushButton(readpcap)
        self.pcaptodisplay.setGeometry(QtCore.QRect(380, 610, 31, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcaptodisplay.setFont(font)
        self.pcaptodisplay.setObjectName("pcaptodisplay")
        self.pcapip = QtWidgets.QCheckBox(readpcap)
        self.pcapip.setGeometry(QtCore.QRect(100, 80, 41, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapip.setFont(font)
        self.pcapip.setObjectName("pcapip")
        self.pcaptcp = QtWidgets.QCheckBox(readpcap)
        self.pcaptcp.setGeometry(QtCore.QRect(150, 80, 61, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcaptcp.setFont(font)
        self.pcaptcp.setObjectName("pcaptcp")
        self.pcapudp = QtWidgets.QCheckBox(readpcap)
        self.pcapudp.setGeometry(QtCore.QRect(220, 80, 61, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapudp.setFont(font)
        self.pcapudp.setObjectName("pcapudp")
        self.pcapicmp = QtWidgets.QCheckBox(readpcap)
        self.pcapicmp.setGeometry(QtCore.QRect(290, 80, 71, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapicmp.setFont(font)
        self.pcapicmp.setObjectName("pcapicmp")
        self.pcaparp = QtWidgets.QCheckBox(readpcap)
        self.pcaparp.setGeometry(QtCore.QRect(370, 80, 61, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcaparp.setFont(font)
        self.pcaparp.setObjectName("pcaparp")
        self.label_4 = QtWidgets.QLabel(readpcap)
        self.label_4.setGeometry(QtCore.QRect(10, 80, 81, 16))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.pcapsrcip = QtWidgets.QCheckBox(readpcap)
        self.pcapsrcip.setGeometry(QtCore.QRect(20, 110, 71, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapsrcip.setFont(font)
        self.pcapsrcip.setObjectName("pcapsrcip")
        self.pcapsrcipread = QtWidgets.QLineEdit(readpcap)
        self.pcapsrcipread.setGeometry(QtCore.QRect(100, 110, 311, 21))
        self.pcapsrcipread.setObjectName("pcapsrcipread")
        self.pcapdstipread = QtWidgets.QLineEdit(readpcap)
        self.pcapdstipread.setGeometry(QtCore.QRect(100, 140, 311, 21))
        self.pcapdstipread.setObjectName("pcapdstipread")
        self.pcapdstip = QtWidgets.QCheckBox(readpcap)
        self.pcapdstip.setGeometry(QtCore.QRect(20, 140, 71, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapdstip.setFont(font)
        self.pcapdstip.setObjectName("pcapdstip")
        self.pcapsrcportread = QtWidgets.QLineEdit(readpcap)
        self.pcapsrcportread.setGeometry(QtCore.QRect(110, 170, 101, 21))
        self.pcapsrcportread.setText("")
        self.pcapsrcportread.setObjectName("pcapsrcportread")
        self.pcapsrcport = QtWidgets.QCheckBox(readpcap)
        self.pcapsrcport.setGeometry(QtCore.QRect(20, 170, 91, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapsrcport.setFont(font)
        self.pcapsrcport.setObjectName("pcapsrcport")
        self.pcapdstport = QtWidgets.QCheckBox(readpcap)
        self.pcapdstport.setGeometry(QtCore.QRect(220, 170, 91, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapdstport.setFont(font)
        self.pcapdstport.setObjectName("pcapdstport")
        self.pcapdstportread = QtWidgets.QLineEdit(readpcap)
        self.pcapdstportread.setGeometry(QtCore.QRect(310, 170, 101, 21))
        self.pcapdstportread.setText("")
        self.pcapdstportread.setObjectName("pcapdstportread")
        self.pcapdata = QtWidgets.QCheckBox(readpcap)
        self.pcapdata.setGeometry(QtCore.QRect(20, 200, 71, 19))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.pcapdata.setFont(font)
        self.pcapdata.setObjectName("pcapdata")
        self.pcapdataread = QtWidgets.QTextEdit(readpcap)
        self.pcapdataread.setGeometry(QtCore.QRect(20, 220, 401, 31))
        self.pcapdataread.setObjectName("pcapdataread")
        self.pcapfilter = QtWidgets.QPushButton(readpcap)
        self.pcapfilter.setGeometry(QtCore.QRect(130, 260, 161, 31))
        self.pcapfilter.setObjectName("pcapfilter")

        self.retranslateUi(readpcap)
        QtCore.QMetaObject.connectSlotsByName(readpcap)

        # trigger written
        self.filename = ''
        self.get_packet = []
        self.get_packet_index = []
        self.packet_protocol = 6
        self.packet = ''
        self.pcapfilechoose.clicked.connect(self.seekfile)
        self.pcapfilter.clicked.connect(self.packet_filter)
        self.pcaptodisplay.clicked.connect(self.full_packet)
        self.pcapsend.clicked.connect(self.packet_send)

    def retranslateUi(self, readpcap):
        _translate = QtCore.QCoreApplication.translate
        readpcap.setWindowTitle(_translate("readpcap", "从PCAP文件读取"))
        self.pcapsend.setText(_translate("readpcap", "发送包"))
        self.label.setText(_translate("readpcap", "文件"))
        self.pcapfilechoose.setText(_translate("readpcap", "..."))
        self.label_2.setText(_translate("readpcap", "包过滤"))
        self.label_3.setText(_translate("readpcap", "选择编号"))
        self.pcaptodisplay.setText(_translate("readpcap", "确定"))
        self.pcapip.setText(_translate("readpcap", "IP"))
        self.pcaptcp.setText(_translate("readpcap", "TCP"))
        self.pcapudp.setText(_translate("readpcap", "UDP"))
        self.pcapicmp.setText(_translate("readpcap", "ICMP"))
        self.pcaparp.setText(_translate("readpcap", "ARP"))
        self.label_4.setText(_translate("readpcap", "协议"))
        self.pcapsrcip.setText(_translate("readpcap", "源IP地址"))
        self.pcapdstip.setText(_translate("readpcap", "目的IP地址"))
        self.pcapsrcport.setText(_translate("readpcap", "源端口"))
        self.pcapdstport.setText(_translate("readpcap", "目的端口"))
        self.pcapdata.setText(_translate("readpcap", "数据"))
        self.pcapfilter.setText(_translate("readpcap", "过滤"))

    #functions written
    def seekfile(self):
        self.filename,_ = QtWidgets.QFileDialog.getOpenFileName(None,
                                                           "选择读取文件",
                                                           "",
                                                           "All files(*)")
        self.pcapfilename.setText(self.filename)

    def packet_filter(self):
        flag = 0
        self.pcapdisplaydigest.setText("")
        if (self.filename == ''):
            self.pcapdisplaydigest.setText("No Filename")
        else:
            tmp = SockPcap.PCAPread(self.filename,0,400)
            if (self.pcapip.isChecked()):
                ip = PCAPfilter.filterIP(tmp)
                flag = 1
            else: ip = []
            if (self.pcaptcp.isChecked()):
                tcp = PCAPfilter.filterTCP(tmp)
                flag = 1
            else:
                tcp = []
            if (self.pcapudp.isChecked()):
                udp = PCAPfilter.filterUDP(tmp)
                flag = 1
            else:
                udp = []
            if (self.pcapicmp.isChecked()):
                icmp = PCAPfilter.filterICMP(tmp)
                flag = 1
            else:
                icmp = []
            if (self.pcaparp.isChecked()):
                arp = PCAPfilter.filterARP(tmp)
                flag = 1
            else:
                arp = []

            if((self.pcapsrcip.isChecked()) and (self.pcapsrcipread.text()!='')):
                srcip = PCAPfilter.filterSrcIP(tmp,self.pcapsrcipread.text())
                flag = 1
            else:srcip = []
            if ((self.pcapdstip.isChecked()) and (self.pcapdstipread.text() != '')):
                dstip = PCAPfilter.filterDstIP(tmp, self.pcapdstipread.text())
                flag = 1
            else:
                dstip = []
            if ((self.pcapsrcport.isChecked()) and (self.pcapsrcportread.text() != '')):
                srcport = PCAPfilter.filterSrcPort(tmp, int(self.pcapsrcportread.text()))
                flag = 1
            else:
                srcport = []
            if ((self.pcapdstport.isChecked()) and (self.pcapdstportread.text() != '')):
                dstport = PCAPfilter.filterDstPort(tmp, int(self.pcapdstportread.text()))
                flag = 1
            else:
                dstport = []
            if ((self.pcapdata.isChecked()) and (self.pcapdataread.toPlainText() != '')):
                data = PCAPfilter.filterData(tmp, self.pcapdataread.toPlainText())
                flag = 1
            else:
                data = []

            self.get_packet_index = list(set(ip)|set(tcp)|set(udp)|set(icmp)|set(arp)
                              |set(srcip)|set(dstip)|set(srcport)|set(dstport)
                              |set(data))
            self.get_packet_index.sort()

            if(flag):
                if self.get_packet_index:
                    self.get_packet = [tmp[i] for i in self.get_packet_index]
                    packet_digest = PCAPfilter.ScanPackets(self.get_packet)
                    j = 0
                    for i in self.get_packet_index:
                        self.pcapdisplaydigest.append(str(i) + ': \n' +
                                                  packet_digest[j] + '\n')
                        j = j + 1
                else:
                    self.pcapdisplaydigest.append("No match item!")
            else:
                self.get_packet_index = range(len(tmp))
                self.get_packet = [tmp[i] for i in self.get_packet_index]
                packet_digest = PCAPfilter.ScanPackets(self.get_packet)
                j = 0
                for i in self.get_packet_index:
                    self.pcapdisplaydigest.append(str(i) + ': \n' +
                                                  packet_digest[j] + '\n')
                    j = j + 1

    def full_packet(self):
        if(self.pcapseqnum.text() == ''):
            self.pcapdisplay.setText("Please choose one seq num!")
        else:
            num = int(self.pcapseqnum.text())
            if num not in self.get_packet_index:
                self.pcapdisplay.setText("Seq num is invalid!")
            else:
                index = self.get_packet_index.index(num)
                self.packet = self.get_packet[index]
                self.packet_protocol = decideProtol(self.packet)
                self.packet = BringNewLife(self.packet)
                self.pcapdisplay.setText(self.packet.decode() + "\n\n" + hexdump(self.packet.pack(), 1))

    def packet_send(self):
        if(self.packet == ''):
            self.pcapdisplay.setText("No packet!")
        else:
            if(self.packet_protocol == 1):
                self.packet.socksendARP()
            if(self.packet_protocol == 2):
                self.packet.sendsockIP()
            if (self.packet_protocol == 3):
                self.packet.sendsockICMP()
            if (self.packet_protocol == 4):
                self.packet.sendsockTCP()
            if (self.packet_protocol == 5):
                self.packet.sendsockUDP()
            self.pcapdisplay.append('\n\n' + "Send a packet!")
