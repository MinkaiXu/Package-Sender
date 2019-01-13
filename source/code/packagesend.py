# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'packagesend.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import *
import SockIcmp,SockArp,SockUdp,SockTcp,SockIp,SockPcap

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(563, 842)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.generate = QtWidgets.QPushButton(self.centralwidget)
        self.generate.setGeometry(QtCore.QRect(210, 450, 161, 34))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.generate.setFont(font)
        self.generate.setObjectName("generate")
        self.display = QtWidgets.QTextEdit(self.centralwidget)
        self.display.setGeometry(QtCore.QRect(10, 490, 541, 251))
        self.display.setObjectName("display")
        self.send = QtWidgets.QPushButton(self.centralwidget)
        self.send.setGeometry(QtCore.QRect(210, 750, 161, 34))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.send.setFont(font)
        self.send.setObjectName("send")
        self.IP = QtWidgets.QWidget(self.centralwidget)
        self.IP.setEnabled(True)
        self.IP.setGeometry(QtCore.QRect(5, -10, 561, 461))
        self.IP.setObjectName("IP")
        self.label_30 = QtWidgets.QLabel(self.IP)
        self.label_30.setGeometry(QtCore.QRect(0, 10, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_30.setFont(font)
        self.label_30.setObjectName("label_30")
        self.label_1 = QtWidgets.QLabel(self.IP)
        self.label_1.setGeometry(QtCore.QRect(0, 50, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_1.setFont(font)
        self.label_1.setObjectName("label_1")
        self.label_3 = QtWidgets.QLabel(self.IP)
        self.label_3.setGeometry(QtCore.QRect(260, 50, 121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.IPsrcIP = QtWidgets.QLineEdit(self.IP)
        self.IPsrcIP.setGeometry(QtCore.QRect(100, 60, 161, 24))
        self.IPsrcIP.setObjectName("IPsrcIP")
        self.IPdstIP = QtWidgets.QLineEdit(self.IP)
        self.IPdstIP.setGeometry(QtCore.QRect(380, 60, 171, 24))
        self.IPdstIP.setObjectName("IPdstIP")
        self.IPdata = QtWidgets.QTextEdit(self.IP)
        self.IPdata.setGeometry(QtCore.QRect(50, 100, 501, 71))
        self.IPdata.setObjectName("IPdata")
        self.label_4 = QtWidgets.QLabel(self.IP)
        self.label_4.setGeometry(QtCore.QRect(0, 110, 51, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.IP)
        self.label_5.setGeometry(QtCore.QRect(0, 180, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.IPmf = QtWidgets.QRadioButton(self.IP)
        self.IPmf.setGeometry(QtCore.QRect(40, 239, 21, 22))
        self.IPmf.setText("")
        self.IPmf.setAutoExclusive(False)
        self.IPmf.setObjectName("IPmf")
        self.label_6 = QtWidgets.QLabel(self.IP)
        self.label_6.setGeometry(QtCore.QRect(70, 229, 31, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.IP)
        self.label_7.setGeometry(QtCore.QRect(160, 229, 31, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_7.setFont(font)
        self.label_7.setObjectName("label_7")
        self.IPdf = QtWidgets.QRadioButton(self.IP)
        self.IPdf.setGeometry(QtCore.QRect(130, 239, 21, 22))
        self.IPdf.setText("")
        self.IPdf.setAutoExclusive(False)
        self.IPdf.setObjectName("IPdf")
        self.IPversion = QtWidgets.QLineEdit(self.IP)
        self.IPversion.setGeometry(QtCore.QRect(370, 234, 181, 24))
        self.IPversion.setObjectName("IPversion")
        self.label_8 = QtWidgets.QLabel(self.IP)
        self.label_8.setGeometry(QtCore.QRect(280, 229, 81, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_8.setFont(font)
        self.label_8.setObjectName("label_8")
        self.IPsvctype = QtWidgets.QLineEdit(self.IP)
        self.IPsvctype.setGeometry(QtCore.QRect(80, 269, 181, 24))
        self.IPsvctype.setText("")
        self.IPsvctype.setObjectName("IPsvctype")
        self.label_9 = QtWidgets.QLabel(self.IP)
        self.label_9.setGeometry(QtCore.QRect(0, 263, 81, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.IPidentity = QtWidgets.QLineEdit(self.IP)
        self.IPidentity.setGeometry(QtCore.QRect(370, 269, 181, 24))
        self.IPidentity.setObjectName("IPidentity")
        self.label_10 = QtWidgets.QLabel(self.IP)
        self.label_10.setGeometry(QtCore.QRect(290, 263, 71, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_10.setFont(font)
        self.label_10.setObjectName("label_10")
        self.IPttl = QtWidgets.QLineEdit(self.IP)
        self.IPttl.setGeometry(QtCore.QRect(370, 304, 181, 24))
        self.IPttl.setObjectName("IPttl")
        self.label_21 = QtWidgets.QLabel(self.IP)
        self.label_21.setGeometry(QtCore.QRect(0, 298, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_21.setFont(font)
        self.label_21.setObjectName("label_21")
        self.label_22 = QtWidgets.QLabel(self.IP)
        self.label_22.setGeometry(QtCore.QRect(270, 298, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_22.setFont(font)
        self.label_22.setObjectName("label_22")
        self.IPfgoffset = QtWidgets.QLineEdit(self.IP)
        self.IPfgoffset.setGeometry(QtCore.QRect(80, 304, 181, 24))
        self.IPfgoffset.setText("")
        self.IPfgoffset.setObjectName("IPfgoffset")
        self.IPchecksum = QtWidgets.QLineEdit(self.IP)
        self.IPchecksum.setGeometry(QtCore.QRect(370, 340, 181, 24))
        self.IPchecksum.setObjectName("IPchecksum")
        self.IPprotocol = QtWidgets.QLineEdit(self.IP)
        self.IPprotocol.setGeometry(QtCore.QRect(100, 340, 161, 24))
        self.IPprotocol.setText("")
        self.IPprotocol.setObjectName("IPprotocol")
        self.label_23 = QtWidgets.QLabel(self.IP)
        self.label_23.setGeometry(QtCore.QRect(0, 334, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_23.setFont(font)
        self.label_23.setObjectName("label_23")
        self.label_24 = QtWidgets.QLabel(self.IP)
        self.label_24.setGeometry(QtCore.QRect(280, 334, 71, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_24.setFont(font)
        self.label_24.setObjectName("label_24")
        self.label_25 = QtWidgets.QLabel(self.IP)
        self.label_25.setGeometry(QtCore.QRect(0, 384, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_25.setFont(font)
        self.label_25.setObjectName("label_25")
        self.IPopt = QtWidgets.QTextEdit(self.IP)
        self.IPopt.setGeometry(QtCore.QRect(100, 374, 451, 71))
        self.IPopt.setObjectName("IPopt")
        self.TCP = QtWidgets.QWidget(self.centralwidget)
        self.TCP.setGeometry(QtCore.QRect(5, -10, 561, 461))
        self.TCP.setObjectName("TCP")
        self.label_26 = QtWidgets.QLabel(self.TCP)
        self.label_26.setGeometry(QtCore.QRect(0, 10, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_26.setFont(font)
        self.label_26.setObjectName("label_26")
        self.label_27 = QtWidgets.QLabel(self.TCP)
        self.label_27.setGeometry(QtCore.QRect(0, 50, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_27.setFont(font)
        self.label_27.setObjectName("label_27")
        self.label_28 = QtWidgets.QLabel(self.TCP)
        self.label_28.setGeometry(QtCore.QRect(260, 50, 121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_28.setFont(font)
        self.label_28.setObjectName("label_28")
        self.TCPsrcIP = QtWidgets.QLineEdit(self.TCP)
        self.TCPsrcIP.setGeometry(QtCore.QRect(100, 60, 161, 24))
        self.TCPsrcIP.setObjectName("TCPsrcIP")
        self.TCPdstIP = QtWidgets.QLineEdit(self.TCP)
        self.TCPdstIP.setGeometry(QtCore.QRect(380, 60, 171, 24))
        self.TCPdstIP.setObjectName("TCPdstIP")
        self.TCPdata = QtWidgets.QTextEdit(self.TCP)
        self.TCPdata.setGeometry(QtCore.QRect(50, 120, 501, 71))
        self.TCPdata.setObjectName("TCPdata")
        self.label_29 = QtWidgets.QLabel(self.TCP)
        self.label_29.setGeometry(QtCore.QRect(0, 130, 51, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_29.setFont(font)
        self.label_29.setObjectName("label_29")
        self.label_31 = QtWidgets.QLabel(self.TCP)
        self.label_31.setGeometry(QtCore.QRect(0, 200, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_31.setFont(font)
        self.label_31.setObjectName("label_31")
        self.TCPcwr = QtWidgets.QRadioButton(self.TCP)
        self.TCPcwr.setGeometry(QtCore.QRect(0, 245, 21, 22))
        self.TCPcwr.setText("")
        self.TCPcwr.setAutoExclusive(False)
        self.TCPcwr.setObjectName("TCPcwr")
        self.label_32 = QtWidgets.QLabel(self.TCP)
        self.label_32.setGeometry(QtCore.QRect(25, 235, 51, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_32.setFont(font)
        self.label_32.setObjectName("label_32")
        self.label_33 = QtWidgets.QLabel(self.TCP)
        self.label_33.setGeometry(QtCore.QRect(95, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_33.setFont(font)
        self.label_33.setObjectName("label_33")
        self.TCPece = QtWidgets.QRadioButton(self.TCP)
        self.TCPece.setGeometry(QtCore.QRect(70, 245, 21, 22))
        self.TCPece.setText("")
        self.TCPece.setAutoExclusive(False)
        self.TCPece.setObjectName("TCPece")
        self.TCPseqnum = QtWidgets.QLineEdit(self.TCP)
        self.TCPseqnum.setGeometry(QtCore.QRect(80, 275, 181, 24))
        self.TCPseqnum.setText("")
        self.TCPseqnum.setObjectName("TCPseqnum")
        self.label_34 = QtWidgets.QLabel(self.TCP)
        self.label_34.setGeometry(QtCore.QRect(0, 269, 81, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_34.setFont(font)
        self.label_34.setObjectName("label_34")
        self.TCPacknum = QtWidgets.QLineEdit(self.TCP)
        self.TCPacknum.setGeometry(QtCore.QRect(370, 275, 181, 24))
        self.TCPacknum.setObjectName("TCPacknum")
        self.label_35 = QtWidgets.QLabel(self.TCP)
        self.label_35.setGeometry(QtCore.QRect(290, 269, 71, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_35.setFont(font)
        self.label_35.setObjectName("label_35")
        self.TCPwindow = QtWidgets.QLineEdit(self.TCP)
        self.TCPwindow.setGeometry(QtCore.QRect(370, 310, 181, 24))
        self.TCPwindow.setObjectName("TCPwindow")
        self.label_36 = QtWidgets.QLabel(self.TCP)
        self.label_36.setGeometry(QtCore.QRect(0, 304, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_36.setFont(font)
        self.label_36.setObjectName("label_36")
        self.label_37 = QtWidgets.QLabel(self.TCP)
        self.label_37.setGeometry(QtCore.QRect(270, 304, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_37.setFont(font)
        self.label_37.setObjectName("label_37")
        self.TCPoffset = QtWidgets.QLineEdit(self.TCP)
        self.TCPoffset.setGeometry(QtCore.QRect(100, 310, 161, 24))
        self.TCPoffset.setText("")
        self.TCPoffset.setObjectName("TCPoffset")
        self.TCPurgent = QtWidgets.QLineEdit(self.TCP)
        self.TCPurgent.setGeometry(QtCore.QRect(370, 346, 181, 24))
        self.TCPurgent.setObjectName("TCPurgent")
        self.TCPchecksum = QtWidgets.QLineEdit(self.TCP)
        self.TCPchecksum.setGeometry(QtCore.QRect(100, 346, 161, 24))
        self.TCPchecksum.setText("")
        self.TCPchecksum.setObjectName("TCPchecksum")
        self.label_38 = QtWidgets.QLabel(self.TCP)
        self.label_38.setGeometry(QtCore.QRect(0, 340, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_38.setFont(font)
        self.label_38.setObjectName("label_38")
        self.label_39 = QtWidgets.QLabel(self.TCP)
        self.label_39.setGeometry(QtCore.QRect(270, 340, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_39.setFont(font)
        self.label_39.setObjectName("label_39")
        self.label_40 = QtWidgets.QLabel(self.TCP)
        self.label_40.setGeometry(QtCore.QRect(0, 390, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_40.setFont(font)
        self.label_40.setObjectName("label_40")
        self.TCPopt = QtWidgets.QTextEdit(self.TCP)
        self.TCPopt.setGeometry(QtCore.QRect(100, 380, 451, 71))
        self.TCPopt.setObjectName("TCPopt")
        self.TCPdstport = QtWidgets.QLineEdit(self.TCP)
        self.TCPdstport.setGeometry(QtCore.QRect(380, 90, 171, 24))
        self.TCPdstport.setObjectName("TCPdstport")
        self.label_71 = QtWidgets.QLabel(self.TCP)
        self.label_71.setGeometry(QtCore.QRect(270, 80, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_71.setFont(font)
        self.label_71.setObjectName("label_71")
        self.label_72 = QtWidgets.QLabel(self.TCP)
        self.label_72.setGeometry(QtCore.QRect(10, 80, 71, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_72.setFont(font)
        self.label_72.setObjectName("label_72")
        self.TCPsrcport = QtWidgets.QLineEdit(self.TCP)
        self.TCPsrcport.setGeometry(QtCore.QRect(100, 90, 161, 24))
        self.TCPsrcport.setObjectName("TCPsrcport")
        self.TCPack = QtWidgets.QRadioButton(self.TCP)
        self.TCPack.setGeometry(QtCore.QRect(210, 245, 21, 22))
        self.TCPack.setText("")
        self.TCPack.setAutoExclusive(False)
        self.TCPack.setObjectName("TCPack")
        self.label_73 = QtWidgets.QLabel(self.TCP)
        self.label_73.setGeometry(QtCore.QRect(235, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_73.setFont(font)
        self.label_73.setObjectName("label_73")
        self.TCPurg = QtWidgets.QRadioButton(self.TCP)
        self.TCPurg.setGeometry(QtCore.QRect(140, 245, 21, 22))
        self.TCPurg.setText("")
        self.TCPurg.setAutoExclusive(False)
        self.TCPurg.setObjectName("TCPurg")
        self.label_74 = QtWidgets.QLabel(self.TCP)
        self.label_74.setGeometry(QtCore.QRect(165, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_74.setFont(font)
        self.label_74.setObjectName("label_74")
        self.TCPfin = QtWidgets.QRadioButton(self.TCP)
        self.TCPfin.setGeometry(QtCore.QRect(490, 245, 21, 22))
        self.TCPfin.setText("")
        self.TCPfin.setAutoExclusive(False)
        self.TCPfin.setObjectName("TCPfin")
        self.TCPrst = QtWidgets.QRadioButton(self.TCP)
        self.TCPrst.setGeometry(QtCore.QRect(350, 245, 21, 22))
        self.TCPrst.setText("")
        self.TCPrst.setAutoExclusive(False)
        self.TCPrst.setObjectName("TCPrst")
        self.TCPsyn = QtWidgets.QRadioButton(self.TCP)
        self.TCPsyn.setGeometry(QtCore.QRect(420, 245, 21, 22))
        self.TCPsyn.setText("")
        self.TCPsyn.setAutoExclusive(False)
        self.TCPsyn.setObjectName("TCPsyn")
        self.label_75 = QtWidgets.QLabel(self.TCP)
        self.label_75.setGeometry(QtCore.QRect(515, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_75.setFont(font)
        self.label_75.setObjectName("label_75")
        self.label_76 = QtWidgets.QLabel(self.TCP)
        self.label_76.setGeometry(QtCore.QRect(445, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_76.setFont(font)
        self.label_76.setObjectName("label_76")
        self.label_41 = QtWidgets.QLabel(self.TCP)
        self.label_41.setGeometry(QtCore.QRect(375, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_41.setFont(font)
        self.label_41.setObjectName("label_41")
        self.TCPpsh = QtWidgets.QRadioButton(self.TCP)
        self.TCPpsh.setGeometry(QtCore.QRect(280, 245, 21, 22))
        self.TCPpsh.setText("")
        self.TCPpsh.setAutoExclusive(False)
        self.TCPpsh.setObjectName("TCPpsh")
        self.label_77 = QtWidgets.QLabel(self.TCP)
        self.label_77.setGeometry(QtCore.QRect(305, 235, 41, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(8)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.label_77.setFont(font)
        self.label_77.setObjectName("label_77")
        self.UDP = QtWidgets.QWidget(self.centralwidget)
        self.UDP.setGeometry(QtCore.QRect(5, -10, 561, 461))
        self.UDP.setObjectName("UDP")
        self.label_112 = QtWidgets.QLabel(self.UDP)
        self.label_112.setGeometry(QtCore.QRect(0, 10, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_112.setFont(font)
        self.label_112.setObjectName("label_112")
        self.label_113 = QtWidgets.QLabel(self.UDP)
        self.label_113.setGeometry(QtCore.QRect(0, 60, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_113.setFont(font)
        self.label_113.setObjectName("label_113")
        self.label_114 = QtWidgets.QLabel(self.UDP)
        self.label_114.setGeometry(QtCore.QRect(260, 60, 121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_114.setFont(font)
        self.label_114.setObjectName("label_114")
        self.UDPsrcIP = QtWidgets.QLineEdit(self.UDP)
        self.UDPsrcIP.setGeometry(QtCore.QRect(100, 70, 161, 24))
        self.UDPsrcIP.setObjectName("UDPsrcIP")
        self.UDPdstIP = QtWidgets.QLineEdit(self.UDP)
        self.UDPdstIP.setGeometry(QtCore.QRect(380, 70, 171, 24))
        self.UDPdstIP.setObjectName("UDPdstIP")
        self.UDPdata = QtWidgets.QTextEdit(self.UDP)
        self.UDPdata.setGeometry(QtCore.QRect(70, 180, 481, 121))
        self.UDPdata.setObjectName("UDPdata")
        self.label_115 = QtWidgets.QLabel(self.UDP)
        self.label_115.setGeometry(QtCore.QRect(10, 220, 51, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_115.setFont(font)
        self.label_115.setObjectName("label_115")
        self.label_116 = QtWidgets.QLabel(self.UDP)
        self.label_116.setGeometry(QtCore.QRect(0, 330, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_116.setFont(font)
        self.label_116.setObjectName("label_116")
        self.UDPchecksum = QtWidgets.QLineEdit(self.UDP)
        self.UDPchecksum.setGeometry(QtCore.QRect(180, 390, 271, 24))
        self.UDPchecksum.setText("")
        self.UDPchecksum.setObjectName("UDPchecksum")
        self.label_123 = QtWidgets.QLabel(self.UDP)
        self.label_123.setGeometry(QtCore.QRect(70, 384, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_123.setFont(font)
        self.label_123.setObjectName("label_123")
        self.UDPdstport = QtWidgets.QLineEdit(self.UDP)
        self.UDPdstport.setGeometry(QtCore.QRect(380, 130, 171, 24))
        self.UDPdstport.setObjectName("UDPdstport")
        self.label_126 = QtWidgets.QLabel(self.UDP)
        self.label_126.setGeometry(QtCore.QRect(270, 120, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_126.setFont(font)
        self.label_126.setObjectName("label_126")
        self.label_127 = QtWidgets.QLabel(self.UDP)
        self.label_127.setGeometry(QtCore.QRect(10, 120, 71, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_127.setFont(font)
        self.label_127.setObjectName("label_127")
        self.UDPsrcport = QtWidgets.QLineEdit(self.UDP)
        self.UDPsrcport.setGeometry(QtCore.QRect(100, 130, 161, 24))
        self.UDPsrcport.setObjectName("UDPsrcport")
        self.ARP = QtWidgets.QWidget(self.centralwidget)
        self.ARP.setGeometry(QtCore.QRect(5, -10, 561, 461))
        self.ARP.setObjectName("ARP")
        self.label_158 = QtWidgets.QLabel(self.ARP)
        self.label_158.setGeometry(QtCore.QRect(0, 10, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_158.setFont(font)
        self.label_158.setObjectName("label_158")
        self.label_159 = QtWidgets.QLabel(self.ARP)
        self.label_159.setGeometry(QtCore.QRect(0, 60, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_159.setFont(font)
        self.label_159.setObjectName("label_159")
        self.label_160 = QtWidgets.QLabel(self.ARP)
        self.label_160.setGeometry(QtCore.QRect(260, 60, 121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_160.setFont(font)
        self.label_160.setObjectName("label_160")
        self.ARPsrcIP = QtWidgets.QLineEdit(self.ARP)
        self.ARPsrcIP.setGeometry(QtCore.QRect(100, 70, 161, 24))
        self.ARPsrcIP.setObjectName("ARPsrcIP")
        self.ARPdstIP = QtWidgets.QLineEdit(self.ARP)
        self.ARPdstIP.setGeometry(QtCore.QRect(380, 70, 171, 24))
        self.ARPdstIP.setObjectName("ARPdstIP")
        self.label_162 = QtWidgets.QLabel(self.ARP)
        self.label_162.setGeometry(QtCore.QRect(0, 250, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_162.setFont(font)
        self.label_162.setObjectName("label_162")
        self.ARPhardtype = QtWidgets.QLineEdit(self.ARP)
        self.ARPhardtype.setGeometry(QtCore.QRect(30, 340, 181, 24))
        self.ARPhardtype.setText("")
        self.ARPhardtype.setObjectName("ARPhardtype")
        self.label_165 = QtWidgets.QLabel(self.ARP)
        self.label_165.setGeometry(QtCore.QRect(70, 300, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_165.setFont(font)
        self.label_165.setObjectName("label_165")
        self.ARPhardsize = QtWidgets.QLineEdit(self.ARP)
        self.ARPhardsize.setGeometry(QtCore.QRect(310, 340, 181, 24))
        self.ARPhardsize.setObjectName("ARPhardsize")
        self.label_166 = QtWidgets.QLabel(self.ARP)
        self.label_166.setGeometry(QtCore.QRect(320, 300, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_166.setFont(font)
        self.label_166.setObjectName("label_166")
        self.ARPprotocolsize = QtWidgets.QLineEdit(self.ARP)
        self.ARPprotocolsize.setGeometry(QtCore.QRect(310, 410, 181, 24))
        self.ARPprotocolsize.setObjectName("ARPprotocolsize")
        self.label_167 = QtWidgets.QLabel(self.ARP)
        self.label_167.setGeometry(QtCore.QRect(50, 370, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_167.setFont(font)
        self.label_167.setObjectName("label_167")
        self.label_168 = QtWidgets.QLabel(self.ARP)
        self.label_168.setGeometry(QtCore.QRect(310, 370, 201, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_168.setFont(font)
        self.label_168.setObjectName("label_168")
        self.ARPprotocoltype = QtWidgets.QLineEdit(self.ARP)
        self.ARPprotocoltype.setGeometry(QtCore.QRect(30, 410, 181, 24))
        self.ARPprotocoltype.setText("")
        self.ARPprotocoltype.setObjectName("ARPprotocoltype")
        self.ARPdstmac = QtWidgets.QLineEdit(self.ARP)
        self.ARPdstmac.setGeometry(QtCore.QRect(170, 160, 331, 24))
        self.ARPdstmac.setObjectName("ARPdstmac")
        self.label_172 = QtWidgets.QLabel(self.ARP)
        self.label_172.setGeometry(QtCore.QRect(0, 150, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_172.setFont(font)
        self.label_172.setObjectName("label_172")
        self.label_173 = QtWidgets.QLabel(self.ARP)
        self.label_173.setGeometry(QtCore.QRect(0, 110, 141, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_173.setFont(font)
        self.label_173.setObjectName("label_173")
        self.ARPsrcmac = QtWidgets.QLineEdit(self.ARP)
        self.ARPsrcmac.setGeometry(QtCore.QRect(170, 120, 331, 24))
        self.ARPsrcmac.setObjectName("ARPsrcmac")
        self.ARPmode = QtWidgets.QLineEdit(self.ARP)
        self.ARPmode.setGeometry(QtCore.QRect(140, 210, 101, 24))
        self.ARPmode.setObjectName("ARPmode")
        self.label_171 = QtWidgets.QLabel(self.ARP)
        self.label_171.setGeometry(QtCore.QRect(0, 200, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_171.setFont(font)
        self.label_171.setObjectName("label_171")
        self.ICMP = QtWidgets.QWidget(self.centralwidget)
        self.ICMP.setGeometry(QtCore.QRect(5, -10, 561, 461))
        self.ICMP.setObjectName("ICMP")
        self.label_42 = QtWidgets.QLabel(self.ICMP)
        self.label_42.setGeometry(QtCore.QRect(0, 10, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_42.setFont(font)
        self.label_42.setObjectName("label_42")
        self.label_43 = QtWidgets.QLabel(self.ICMP)
        self.label_43.setGeometry(QtCore.QRect(0, 60, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_43.setFont(font)
        self.label_43.setObjectName("label_43")
        self.label_44 = QtWidgets.QLabel(self.ICMP)
        self.label_44.setGeometry(QtCore.QRect(260, 60, 121, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_44.setFont(font)
        self.label_44.setObjectName("label_44")
        self.ICMPsrcIP = QtWidgets.QLineEdit(self.ICMP)
        self.ICMPsrcIP.setGeometry(QtCore.QRect(100, 70, 161, 24))
        self.ICMPsrcIP.setObjectName("ICMPsrcIP")
        self.ICMPdstIP = QtWidgets.QLineEdit(self.ICMP)
        self.ICMPdstIP.setGeometry(QtCore.QRect(380, 70, 171, 24))
        self.ICMPdstIP.setObjectName("ICMPdstIP")
        self.ICMPdata = QtWidgets.QTextEdit(self.ICMP)
        self.ICMPdata.setGeometry(QtCore.QRect(100, 180, 451, 101))
        self.ICMPdata.setObjectName("ICMPdata")
        self.label_45 = QtWidgets.QLabel(self.ICMP)
        self.label_45.setGeometry(QtCore.QRect(20, 210, 51, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_45.setFont(font)
        self.label_45.setObjectName("label_45")
        self.label_46 = QtWidgets.QLabel(self.ICMP)
        self.label_46.setGeometry(QtCore.QRect(0, 290, 111, 41))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_46.setFont(font)
        self.label_46.setObjectName("label_46")
        self.label_47 = QtWidgets.QLabel(self.ICMP)
        self.label_47.setGeometry(QtCore.QRect(0, 370, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_47.setFont(font)
        self.label_47.setObjectName("label_47")
        self.ICMPextrahead = QtWidgets.QTextEdit(self.ICMP)
        self.ICMPextrahead.setGeometry(QtCore.QRect(100, 350, 451, 81))
        self.ICMPextrahead.setObjectName("ICMPextrahead")
        self.ICMPcode = QtWidgets.QLineEdit(self.ICMP)
        self.ICMPcode.setGeometry(QtCore.QRect(380, 120, 171, 24))
        self.ICMPcode.setObjectName("ICMPcode")
        self.label_78 = QtWidgets.QLabel(self.ICMP)
        self.label_78.setGeometry(QtCore.QRect(270, 110, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_78.setFont(font)
        self.label_78.setObjectName("label_78")
        self.label_79 = QtWidgets.QLabel(self.ICMP)
        self.label_79.setGeometry(QtCore.QRect(0, 110, 101, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_79.setFont(font)
        self.label_79.setObjectName("label_79")
        self.ICMPtype = QtWidgets.QLineEdit(self.ICMP)
        self.ICMPtype.setGeometry(QtCore.QRect(100, 120, 161, 24))
        self.ICMPtype.setObjectName("ICMPtype")

        #textBrower_ -> help_menu
        self.textBrowser_IP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_IP.setEnabled(True)
        self.textBrowser_IP.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_IP.setObjectName("textBrowser_IP")
        self.textBrowser_TCP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_TCP.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_TCP.setObjectName("textBrowser_TCP")
        self.textBrowser_UDP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_UDP.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_UDP.setObjectName("textBrowser_UDP")
        self.textBrowser_ARP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_ARP.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_ARP.setObjectName("textBrowser_ARP")
        self.textBrowser_ICMP = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_ICMP.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_ICMP.setObjectName("textBrowser_ICMP")
        self.textBrowser_Saveinpcap = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_Saveinpcap.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_Saveinpcap.setObjectName("textBrowser_Saveinpcap")
        self.textBrowser_readfrompcap = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_readfrompcap.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_readfrompcap.setObjectName("textBrowser_readfrompcap")
        self.textBrowser_Tools = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_Tools.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser_Tools.setObjectName("textBrowser_Tools")
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(0, 0, 563,843))
        self.textBrowser.setObjectName("textBrowser")

        #menubar
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 891, 30))
        self.menubar.setObjectName("menubar")
        self.menu_F = QtWidgets.QMenu(self.menubar)
        self.menu_F.setObjectName("menu_F")
        self.menu_P = QtWidgets.QMenu(self.menubar)
        self.menu_P.setObjectName("menu_P")
        self.menu_T = QtWidgets.QMenu(self.menubar)
        self.menu_T.setObjectName("menu_T")
        self.menu_H = QtWidgets.QMenu(self.menubar)
        self.menu_H.setObjectName("menu_H")
        self.menuFile = QtWidgets.QMenu(self.menu_H)
        self.menuFile.setObjectName("menuFile")
        self.menuProtocols = QtWidgets.QMenu(self.menu_H)
        self.menuProtocols.setObjectName("menuProtocols")
        self.menuTools = QtWidgets.QMenu(self.menu_H)
        self.menuTools.setObjectName("menuTools")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)


        self.actionSave_in_PCAP = QtWidgets.QAction(MainWindow)
        self.actionSave_in_PCAP.setObjectName("actionSave_in_PCAP")
        self.actionRead_from_PCAP = QtWidgets.QAction(MainWindow)
        self.actionRead_from_PCAP.setObjectName("actionRead_from_PCAP")
        self.actionEXIT = QtWidgets.QAction(MainWindow)
        self.actionEXIT.setObjectName("actionEXIT")
        self.actionIP = QtWidgets.QAction(MainWindow)
        self.actionIP.setObjectName("actionIP")
        self.actionTCP = QtWidgets.QAction(MainWindow)
        self.actionTCP.setObjectName("actionTCP")
        self.actionUDP = QtWidgets.QAction(MainWindow)
        self.actionUDP.setObjectName("actionUDP")
        self.actionARP = QtWidgets.QAction(MainWindow)
        self.actionARP.setObjectName("actionARP")
        self.actionICMP = QtWidgets.QAction(MainWindow)
        self.actionICMP.setObjectName("actionICMP")
        self.actionAES_encryption = QtWidgets.QAction(MainWindow)
        self.actionAES_encryption.setObjectName("actionAES_encryption")
        self.actionHash_SHA256 = QtWidgets.QAction(MainWindow)
        self.actionHash_SHA256.setObjectName("actionHash_SHA256")
        self.actionRSA_key_gen = QtWidgets.QAction(MainWindow)
        self.actionRSA_key_gen.setObjectName("actionRSA_key_gen")
        self.actionRSA_encryption = QtWidgets.QAction(MainWindow)
        self.actionRSA_encryption.setObjectName("actionRSA_encryption")
        self.actionSignature_by_RSA = QtWidgets.QAction(MainWindow)
        self.actionSignature_by_RSA.setObjectName("actionSignature_by_RSA")
        self.actionHEX_input_and_output = QtWidgets.QAction(MainWindow)
        self.actionHEX_input_and_output.setObjectName("actionHEX_input_and_output")
        self.actionSave_in_PCAP_2 = QtWidgets.QAction(MainWindow)
        self.actionSave_in_PCAP_2.setObjectName("actionSave_in_PCAP_2")
        self.actionRead_from_PCAP_2 = QtWidgets.QAction(MainWindow)
        self.actionRead_from_PCAP_2.setObjectName("actionRead_from_PCAP_2")
        self.actionIP_2 = QtWidgets.QAction(MainWindow)
        self.actionIP_2.setObjectName("actionIP_2")
        self.actionTCP_2 = QtWidgets.QAction(MainWindow)
        self.actionTCP_2.setObjectName("actionTCP_2")
        self.actionUDP_2 = QtWidgets.QAction(MainWindow)
        self.actionUDP_2.setObjectName("actionUDP_2")
        self.actionARP_2 = QtWidgets.QAction(MainWindow)
        self.actionARP_2.setObjectName("actionARP_2")
        self.actionICMP_2 = QtWidgets.QAction(MainWindow)
        self.actionICMP_2.setObjectName("actionICMP_2")
        self.actionAES_encryption_2 = QtWidgets.QAction(MainWindow)
        self.actionAES_encryption_2.setObjectName("actionAES_encryption_2")
        self.actionHash_SHA256_2 = QtWidgets.QAction(MainWindow)
        self.actionHash_SHA256_2.setObjectName("actionHash_SHA256_2")
        self.actionRSA_key_gen_2 = QtWidgets.QAction(MainWindow)
        self.actionRSA_key_gen_2.setObjectName("actionRSA_key_gen_2")
        self.actionRSA_encryption_2 = QtWidgets.QAction(MainWindow)
        self.actionRSA_encryption_2.setObjectName("actionRSA_encryption_2")
        self.actionSignature_by_RSA_2 = QtWidgets.QAction(MainWindow)
        self.actionSignature_by_RSA_2.setObjectName("actionSignature_by_RSA_2")
        self.actionHEX_input_and_output_2 = QtWidgets.QAction(MainWindow)
        self.actionHEX_input_and_output_2.setObjectName("actionHEX_input_and_output_2")
        self.actionTools=QtWidgets.QAction(MainWindow)
        self.actionTools.setObjectName("actionTools")
        self.actionDetails = QtWidgets.QAction(MainWindow)
        self.actionDetails.setObjectName("actionDetails")
        self.menu_F.addAction(self.actionSave_in_PCAP)
        self.menu_F.addAction(self.actionRead_from_PCAP)
        self.menu_F.addAction(self.actionEXIT)



        self.menu_P.addAction(self.actionIP)
        self.menu_P.addAction(self.actionTCP)
        self.menu_P.addAction(self.actionUDP)
        self.menu_P.addAction(self.actionARP)
        self.menu_P.addAction(self.actionICMP)
        self.menu_T.addAction(self.actionAES_encryption)
        self.menu_T.addAction(self.actionHash_SHA256)
        self.menu_T.addAction(self.actionRSA_key_gen)
        self.menu_T.addAction(self.actionRSA_encryption)
        self.menu_T.addAction(self.actionSignature_by_RSA)
        self.menu_T.addAction(self.actionHEX_input_and_output)
        self.menuFile.addAction(self.actionSave_in_PCAP_2)
        self.menuFile.addAction(self.actionRead_from_PCAP_2)
        self.menuProtocols.addAction(self.actionIP_2)
        self.menuProtocols.addAction(self.actionTCP_2)
        self.menuProtocols.addAction(self.actionUDP_2)
        self.menuProtocols.addAction(self.actionARP_2)
        self.menuProtocols.addAction(self.actionICMP_2)
        self.menu_H.addAction(self.menuFile.menuAction())
        self.menu_H.addAction(self.menuProtocols.menuAction())
        self.menu_H.addAction(self.menuTools.menuAction())
        self.menu_H.addAction(self.actionDetails)
        self.menuTools.addAction(self.actionTools)
        self.menubar.addAction(self.menu_F.menuAction())
        self.menubar.addAction(self.menu_P.menuAction())
        self.menubar.addAction(self.menu_T.menuAction())
        self.menubar.addAction(self.menu_H.menuAction())


        #settings written
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)

        self.IP.setVisible(True)
        self.TCP.setVisible(False)
        self.UDP.setVisible(False)
        self.ICMP.setVisible(False)
        self.ARP.setVisible(False)
        self.IPmf.setAutoExclusive(False)
        self.IPdf.setAutoExclusive(False)
        self.TCPcwr.setAutoExclusive(False)
        self.TCPece.setAutoExclusive(False)
        self.TCPurg.setAutoExclusive(False)
        self.TCPpsh.setAutoExclusive(False)
        self.TCPrst.setAutoExclusive(False)
        self.TCPsyn.setAutoExclusive(False)
        self.TCPfin.setAutoExclusive(False)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        #trigger written
        self.packet = 0
        self.Index=0
        self.generate.clicked.connect(self.generatepacket)
        self.send.clicked.connect(self.sendpacket)
        self.actionIP.triggered.connect(self.IP_change)
        self.actionTCP.triggered.connect(self.TCP_change)
        self.actionUDP.triggered.connect(self.UDP_change)
        self.actionARP.triggered.connect(self.ARP_change)
        self.actionICMP.triggered.connect(self.ICMP_change)

        self.actionIP_2.triggered.connect(self.IP_show)
        self.actionTCP_2.triggered.connect(self.TCP_show)
        self.actionUDP_2.triggered.connect(self.UDP_show)
        self.actionARP_2.triggered.connect(self.ARP_show)
        self.actionICMP_2.triggered.connect(self.ICMP_show)
        self.actionSave_in_PCAP_2.triggered.connect(self.Save_show)
        self.actionRead_from_PCAP_2.triggered.connect(self.Read_show)
        self.actionDetails.triggered.connect(self.Details_show)
        self.actionTools.triggered.connect(self.Tools_show)
        exit=QtWidgets.QWidget()
        #self.actionEXIT.triggered.connect(exit.show)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def IP_show(self,Mainwindow):
        self.textBrowser_IP.setVisible(True)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def TCP_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(True)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def UDP_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(True)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def ARP_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(True)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def ICMP_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(True)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def Save_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(True)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def Read_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(True)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
    def Tools_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(True)
        self.textBrowser.setVisible(False)
    def Details_show(self,MainWindow):
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(True)

    def IP_change(self,MainWindow):
        self.IP.setVisible(True)
        self.TCP.setVisible(False)
        self.UDP.setVisible(False)
        self.ICMP.setVisible(False)
        self.ARP.setVisible(False)
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
        self.Index=0

    def TCP_change(self,MainWindow):
        self.IP.setVisible(False)
        self.TCP.setVisible(True)
        self.UDP.setVisible(False)
        self.ICMP.setVisible(False)
        self.ARP.setVisible(False)
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
        self.Index=1

    def UDP_change(self,MainWindow):
        self.IP.setVisible(False)
        self.TCP.setVisible(False)
        self.UDP.setVisible(True)
        self.ICMP.setVisible(False)
        self.ARP.setVisible(False)
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
        self.Index=2

    def ARP_change(self,MainWindow):
        self.IP.setVisible(False)
        self.TCP.setVisible(False)
        self.UDP.setVisible(False)
        self.ICMP.setVisible(False)
        self.ARP.setVisible(True)
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
        self.Index=3

    def ICMP_change(self,MainWindow):
        self.IP.setVisible(False)
        self.TCP.setVisible(False)
        self.UDP.setVisible(False)
        self.ICMP.setVisible(True)
        self.ARP.setVisible(False)
        self.textBrowser_IP.setVisible(False)
        self.textBrowser_ARP.setVisible(False)
        self.textBrowser_TCP.setVisible(False)
        self.textBrowser_ICMP.setVisible(False)
        self.textBrowser_UDP.setVisible(False)
        self.textBrowser_Saveinpcap.setVisible(False)
        self.textBrowser_readfrompcap.setVisible(False)
        self.textBrowser_Tools.setVisible(False)
        self.textBrowser.setVisible(False)
        self.Index=4

    def generatepacket(self):
        if (self.Index == 0):
            self.generateIPpacket()
        if (self.Index == 1):
            self.generateTCPpacket()
        if (self.Index == 2):
            self.generateUDPpacket()
        if (self.Index== 3):
            self.generateARPpacket()
        if (self.Index == 4):
            self.generateICMPpacket()

    def generateIPpacket(self):
        try:
            if (self.IPprotocol.text() == ''):
                self.packet = SockIp.sockIP(self.IPsrcIP.text(),
                                            self.IPdstIP.text(),
                                            self.IPdata.toPlainText(),
                                            socket.IPPROTO_TCP,
                                            self.IPopt.toPlainText())
            else:
                self.packet = SockIp.sockIP(self.IPsrcIP.text(),
                                            self.IPdstIP.text(),
                                            self.IPdata.toPlainText(),
                                            int(self.IPprotocol.text()),
                                            self.IPopt.toPlainText())

            if (self.IPmf.isChecked()): self.packet.IP_MF = 1
            if (self.IPdf.isChecked()): self.packet.IP_DF = 1
            if (self.IPversion.text() != ''):
                self.packet.IP_Version = int(self.IPversion.text())
            if (self.IPsvctype.text() != ''):
                self.packet.IP_SvcType = int(self.IPsvctype.text())
            if (self.IPidentity.text() != ''):
                self.packet.IP_Identify = int(self.IPidentity.text())
            if (self.IPfgoffset.text() != ''):
                self.packet.IP_FgOffset = int(self.IPfgoffset.text())
            if (self.IPttl.text() != ''):
                self.packet.IP_TTL = int(self.IPttl.text())
        except:
            self.display.setText("Input error")

        else:
            self.display.setText(self.packet.decode() + "\n\n" + hexdump(self.packet.pack(), 1))
            check = str(hex(self.packet.IP_CheckSum))
            check = check[4:6] + check[2:4]
            self.IPchecksum.setText(check)

    def generateTCPpacket(self):
        try:
            self.packet = SockTcp.sockTCP(self.TCPsrcIP.text(),
                                          int(self.TCPsrcport.text()),
                                          self.TCPdstIP.text(),
                                          int(self.TCPdstport.text()),
                                          self.TCPdata.toPlainText(),
                                          self.TCPopt.toPlainText())

            if (self.TCPcwr.isChecked()):
                self.packet.TCP_CWR = 1
            else:
                self.packet.TCP_CWR = 0
            if (self.TCPece.isChecked()):
                self.packet.TCP_ECE = 1
            else:
                self.packet.TCP_ECE = 0
            if (self.TCPurg.isChecked()):
                self.packet.TCP_URG = 1
            else:
                self.packet.TCP_URG = 0
            if (self.TCPack.isChecked()):
                self.packet.TCP_ACK = 1
            else:
                self.packet.TCP_ACK = 0
            if (self.TCPpsh.isChecked()):
                self.packet.TCP_PSH = 1
            else:
                self.packet.TCP_PSH = 0
            if (self.TCPrst.isChecked()):
                self.packet.TCP_RST = 1
            else:
                self.packet.TCP_RST = 0
            if (self.TCPsyn.isChecked()):
                self.packet.TCP_SYN = 1
            else:
                self.packet.TCP_SYN = 0
            if (self.TCPfin.isChecked()):
                self.packet.TCP_FIN = 1
            else:
                self.packet.TCP_FIN = 0

            if (self.TCPseqnum.text() != ''):
                self.packet.TCP_SeqNum = int(self.TCPseqnum.text())
            else:
                self.packet.TCP_SeqNum = 0
            if (self.TCPacknum.text() != ''):
                self.packet.TCP_AckNum = int(self.TCPacknum.text())
            else:
                self.packet.TCP_AckNum = 0
            if (self.TCPoffset.text() != ''):
                self.packet.TCP_Offset = int(self.TCPoffset.text())
            if (self.TCPwindow.text() != ''):
                self.packet.TCP_Window = int(self.TCPwindow.text())
            if (self.TCPurgent.text() != ''):
                self.packet.TCP_Urgent = int(self.TCPurgent.text())

        except:
            self.display.setText("Input error")
        else:
            self.display.setText(self.packet.decode() + "\n\n" + hexdump(self.packet.pack(), 1))
            check = str(hex(self.packet.TCP_CheckSum))
            check = check[4:6] + check[2:4]
            self.TCPchecksum.setText(check)

    def generateUDPpacket(self):
        try:
            self.packet = SockUdp.sockUDP(self.UDPsrcIP.text(),
                                          int(self.UDPsrcport.text()),
                                          self.UDPdstIP.text(),
                                          int(self.UDPdstport.text()),
                                          self.UDPdata.toPlainText())
        except:
            self.display.setText("Input error")

        else:
            self.display.setText(self.packet.decode() + "\n\n" + hexdump(self.packet.pack(), 1))
            check = str(hex(self.packet.UDP_CheckSum))
            check = check[4:6] + check[2:4]
            self.UDPchecksum.setText(check)

    def generateARPpacket(self):
        try:
            self.packet = SockArp.sockARP(self.ARPsrcIP.text(),
                                          self.ARPdstIP.text(),
                                          self.ARPsrcmac.text(),
                                          self.ARPdstmac.text(),
                                          int(self.ARPmode.text()))

            if (self.ARPhardsize.text() != ''):
                self.packet.ARP_HardSize = int(self.ARPhardsize.text())
            if (self.ARPhardtype.text() != ''):
                self.packet.ARP_HardType = int(self.ARPhardtype.text())
            if (self.ARPprotocolsize.text() != ''):
                self.packet.ARP_ProtoSize = int(self.ARPprotocolsize.text())
            if (self.ARPprotocoltype.text() != ''):
                self.packet.ARP_ProtoType = int(self.ARPprotocoltype.text())

        except:
            self.display.setText("Input error")
        else:
            self.display.setText(self.packet.decode() + "\n\n" + hexdump(self.packet.pack(), 1))

    def generateICMPpacket(self):
        try:
            self.packet = SockIcmp.sockICMP(self.ICMPsrcIP.text(),
                                            self.ICMPdstIP.text(),
                                            int(self.ICMPtype.text()),
                                            int(self.ICMPcode.text()),
                                            self.ICMPdata.toPlainText())
            if (self.ICMPextrahead.toPlainText() != ''):
                self.packet.eh(self.ICMPextrahead.toPlainText())

        except:
            self.display.setText("Input error")
        else:
            self.display.setText(self.packet.decode() + "\n\n" + hexdump(self.packet.pack(), 1))

    def sendpacket(self):
        if (self.packet == 0):
            self.display.append("Don't struct a packet!")
        else:
            if (self.Index == 0):
                self.packet.sendsockIP()
            if (self.Index == 1):
                self.packet.sendsockTCP()
            if (self.Index == 2):
                self.packet.sendsockUDP()
            if (self.Index== 3):
                self.packet.socksendARP()
            if (self.Index == 4):
                self.packet.sendsockICMP()
            self.display.append('\n\n' + "Send a packet!")

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "网络发包器"))
        self.generate.setText(_translate("MainWindow", "生成数据包"))
        self.send.setText(_translate("MainWindow", "发送数据包"))
        self.label_30.setText(_translate("MainWindow", "必填项"))
        self.label_1.setText(_translate("MainWindow", "源IP地址"))
        self.label_3.setText(_translate("MainWindow", "目的IP地址"))
        self.label_4.setText(_translate("MainWindow", "数据"))
        self.label_5.setText(_translate("MainWindow", "可选项"))
        self.label_6.setText(_translate("MainWindow", "MF"))
        self.label_7.setText(_translate("MainWindow", "DF"))
        self.label_8.setText(_translate("MainWindow", "版本号"))
        self.label_9.setText(_translate("MainWindow", "服务号"))
        self.label_10.setText(_translate("MainWindow", "标识"))
        self.label_21.setText(_translate("MainWindow", "片偏移"))
        self.label_22.setText(_translate("MainWindow", "生存时间"))
        self.label_23.setText(_translate("MainWindow", "上层协议"))
        self.label_24.setText(_translate("MainWindow", "校验和"))
        self.label_25.setText(_translate("MainWindow", "可选头部"))
        self.label_26.setText(_translate("MainWindow", "必填项"))
        self.label_27.setText(_translate("MainWindow", "源IP地址"))
        self.label_28.setText(_translate("MainWindow", "目的IP地址"))
        self.label_29.setText(_translate("MainWindow", "数据"))
        self.label_31.setText(_translate("MainWindow", "可选项"))
        self.label_32.setText(_translate("MainWindow", "CWR"))
        self.label_33.setText(_translate("MainWindow", "ECE"))
        self.label_34.setText(_translate("MainWindow", "序列号"))
        self.label_35.setText(_translate("MainWindow", "确认号"))
        self.label_36.setText(_translate("MainWindow", "报文长度"))
        self.label_37.setText(_translate("MainWindow", "窗口大小"))
        self.label_38.setText(_translate("MainWindow", "校验和"))
        self.label_39.setText(_translate("MainWindow", "紧急指针"))
        self.label_40.setText(_translate("MainWindow", "可选头部"))
        self.label_71.setText(_translate("MainWindow", "目的端口"))
        self.label_72.setText(_translate("MainWindow", "源端口"))
        self.label_73.setText(_translate("MainWindow", "ACK"))
        self.label_74.setText(_translate("MainWindow", "URG"))
        self.label_75.setText(_translate("MainWindow", "FIN"))
        self.label_76.setText(_translate("MainWindow", "SYN"))
        self.label_41.setText(_translate("MainWindow", "RST"))
        self.label_77.setText(_translate("MainWindow", "PSH"))
        self.label_112.setText(_translate("MainWindow", "必填项"))
        self.label_113.setText(_translate("MainWindow", "源IP地址"))
        self.label_114.setText(_translate("MainWindow", "目的IP地址"))
        self.label_115.setText(_translate("MainWindow", "数据"))
        self.label_116.setText(_translate("MainWindow", "可选项"))
        self.label_123.setText(_translate("MainWindow", "校验和"))
        self.label_126.setText(_translate("MainWindow", "目的端口"))
        self.label_127.setText(_translate("MainWindow", "源端口"))
        self.label_158.setText(_translate("MainWindow", "必填项"))
        self.label_159.setText(_translate("MainWindow", "源IP地址"))
        self.label_160.setText(_translate("MainWindow", "目的IP地址"))
        self.label_162.setText(_translate("MainWindow", "可选项"))
        self.label_165.setText(_translate("MainWindow", "硬件类型"))
        self.label_166.setText(_translate("MainWindow", "硬件类型长度"))
        self.label_167.setText(_translate("MainWindow", "上层协议类型"))
        self.label_168.setText(_translate("MainWindow", "上层协议类型长度"))
        self.label_172.setText(_translate("MainWindow", "目的MAC地址"))
        self.label_173.setText(_translate("MainWindow", "源MAC地址"))
        self.label_171.setText(_translate("MainWindow", "ARP操作码"))
        self.label_42.setText(_translate("MainWindow", "必填项"))
        self.label_43.setText(_translate("MainWindow", "源IP地址"))
        self.label_44.setText(_translate("MainWindow", "目的IP地址"))
        self.label_45.setText(_translate("MainWindow", "数据"))
        self.label_46.setText(_translate("MainWindow", "可选项"))
        self.label_47.setText(_translate("MainWindow", "可选头部"))
        self.label_78.setText(_translate("MainWindow", "报文类型"))
        self.label_79.setText(_translate("MainWindow", "报文格式"))
        self.textBrowser_IP.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">IP发包说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">在左侧选择框内输入对应信息，点击Generate Packet按钮，即会在右侧框内输出要发送的包格式，点击Send Packet按钮完成发包，右侧框中出现Send a packet！字样，发包完成。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   输入出现问题时，右侧框中显示Input error！</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   发包只支持IPv4协议，不支持IPv6。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">具体选择项信息：（*代表必选项）</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strIP：</span><span style=\" font-size:11pt;\">源IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstIP：</span><span style=\" font-size:11pt;\">目的IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Data：</span><span style=\" font-size:11pt;\">IP包负载（payload），输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串，如5266abfdc。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">MF：</span><span style=\" font-size:11pt;\">IP标志位最低位，表示是否还有更多分片。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">DF：</span><span style=\" font-size:11pt;\">IP标志位中间位，表示是否允许分片。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Version：</span><span style=\" font-size:11pt;\">IP版本号，4bit，数字int格式，默认为4。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Service：</span><span style=\" font-size:11pt;\">IP服务号，8bit，数字int格式，默认为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Identity：</span><span style=\" font-size:11pt;\">IP标识位，当IP需要分片时依此确定同属一个IP报文，16bit，数字int格式，默认为0x0001。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">FgOffset：</span><span style=\" font-size:11pt;\">片偏移量，标示分片的IP包在原IP报文中的位置，13bit，数字int格式，默认为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">TTL：</span><span style=\" font-size:11pt;\">生存时间，8bit，数字int格式，默认为64。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Protocol：</span><span style=\" font-size:11pt;\">协议字段，标示该IP包携带何种协议数据，8bit，数字int格式，默认为6（TCP协议）。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Checksum：</span><span style=\" font-size:11pt;\">IP包校验和，16bit，十六进制数字形式，在点击Generate Packet后会填入正确校验和，不支持个人输入修改。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Optional Head：</span><span style=\" font-size:11pt;\">IP可选头部，输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt; font-weight:600; font-style:italic;\"><br /></p></body></html>"))
        self.textBrowser_TCP.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">TCP发包说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">在左侧选择框内输入对应信息，点击Generate Packet按钮，即会在右侧框内输出要发送的包格式，点击Send Packet按钮完成发包，右侧框中出现Send a packet！字样，发包完成。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   输入出现问题时，右侧框中显示Input error！</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">具体选择项信息：（*代表必选项）</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strIP：</span><span style=\" font-size:11pt;\">源IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstIP：</span><span style=\" font-size:11pt;\">目的IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strPort：</span><span style=\" font-size:11pt;\">源端口，16bit，数字int格式，如8080。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstPort：</span><span style=\" font-size:11pt;\">目的端口，16bit，数字int格式，如8080。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Data：</span><span style=\" font-size:11pt;\">TCP包负载（payload），输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串，如5266abfdc。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">CWR：</span><span style=\" font-size:11pt;\">标志位标志位，表示拥塞窗口减少。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">ECE：</span><span style=\" font-size:11pt;\">标志位标志位，表示显式拥塞提醒回应。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">URG：</span><span style=\" font-size:11pt;\">标志位紧急标志位，表示高优先级数据包。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">ACK：</span><span style=\" font-size:11pt;\">标志位应答标志位。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">PSH：</span><span style=\" font-size:11pt;\">标志位推送标志位，表示立即转发。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">RST：</span><span style=\" font-size:11pt;\">标志位复位标志位，表示中断连接。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">SYN：</span><span style=\" font-size:11pt;\">标志位开始标志位，表示开始会话请求。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">FIN：</span><span style=\" font-size:11pt;\">标志位结束标志位，表示结束会话。选中为1，不选为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">SeqNum：</span><span style=\" font-size:11pt;\">序列号，32bit，数字int格式，默认为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">AckNum：</span><span style=\" font-size:11pt;\">确认号，32bit，数字int格式，默认为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Offset：</span><span style=\" font-size:11pt;\">报头长度，4bit，数字int格式，默认为5。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Window：</span><span style=\" font-size:11pt;\">发送窗口大小，16bit，数字int格式，默认为65523。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Checksum：</span><span style=\" font-size:11pt;\">校验和，16bit，十六进制数字形式，在点击Generate Packet后会填入正确校验和，不支持个人输入修改。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Urgent：</span><span style=\" font-size:11pt;\">紧急指针，URG=1时有效，与序列号相加标示紧急数据最后一个字节的序号，16bit，数字int格式，默认为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Optional Head：</span><span style=\" font-size:11pt;\">可选头部，输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt; font-weight:600; font-style:italic;\"><br /></p></body></html>"))
        self.textBrowser_UDP.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">UDP发包说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">在左侧选择框内输入对应信息，点击Generate Packet按钮，即会在右侧框内输出要发送的包格式，点击Send Packet按钮完成发包，右侧框中出现Send a packet！字样，发包完成。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   输入出现问题时，右侧框中显示Input error！</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">具体选择项信息：（*代表必选项）</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strIP：</span><span style=\" font-size:11pt;\">源IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstIP：</span><span style=\" font-size:11pt;\">目的IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strPort：</span><span style=\" font-size:11pt;\">源端口，16bit，数字int格式，如8080。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstPort：</span><span style=\" font-size:11pt;\">目的端口，16bit，数字int格式，如8080。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Data：</span><span style=\" font-size:11pt;\">UDP包负载（payload），输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串，如5266abfdc。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Checksum：</span><span style=\" font-size:11pt;\">校验和，16bit，十六进制数字形式，在点击Generate Packet后会填入正确校验和，不支持个人输入修改。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt; font-weight:600; font-style:italic;\"><br /></p></body></html>"))
        self.textBrowser_ARP.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">ARP发包说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">在左侧选择框内输入对应信息，点击Generate Packet按钮，即会在右侧框内输出要发送的包格式，点击Send Packet按钮完成发包，右侧框中出现Send a packet！字样，发包完成。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   输入出现问题时，右侧框中显示Input error！</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">具体选择项信息：（*代表必选项）</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strIP：</span><span style=\" font-size:11pt;\">源IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstIP：</span><span style=\" font-size:11pt;\">目的IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strMac：</span><span style=\" font-size:11pt;\">源Mac地址，48bit标准Mac地址格式，如ee:ff:da:22:15:aa。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstMac：</span><span style=\" font-size:11pt;\">目的Mac地址，48bit标准Mac地址格式。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Mode：</span><span style=\" font-size:11pt;\">ARP操作码，16bit,数字int格式，1表示ARP请求包，2表示ARP应答包，默认为1。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">HardType：</span><span style=\" font-size:11pt;\">硬件类型，16bit，数字int格式，默认为1。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">HardSize：</span><span style=\" font-size:11pt;\">硬件类型长度，8bit，数字int格式，默认为6。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">ProtocolType：</span><span style=\" font-size:11pt;\">上层协议类型，16bit，数字int格式，默认为0x0800。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">ProtocolSize：</span><span style=\" font-size:11pt;\">上层协议类型长度，8bit，数字int格式，默认为4。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt; font-weight:600; font-style:italic;\"><br /></p></body></html>"))
        self.textBrowser_ICMP.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">ICMP发包说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">在左侧选择框内输入对应信息，点击Generate Packet按钮，即会在右侧框内输出要发送的包格式，点击Send Packet按钮完成发包，右侧框中出现Send a packet！字样，发包完成。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   输入出现问题时，右侧框中显示Input error！</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">具体选择项信息：（*代表必选项）</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*strIP：</span><span style=\" font-size:11pt;\">源IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*dstIP：</span><span style=\" font-size:11pt;\">目的IP地址，地址格式为IPv4格式，如192.168.2.153。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Type：</span><span style=\" font-size:11pt;\">ICMP报文作用和格式，8bit，数字int格式，默认为8。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Code：</span><span style=\" font-size:11pt;\">详细说明ICMP报文类型，8bit，数字int格式，默认为0。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">*Data：</span><span style=\" font-size:11pt;\">TCP包负载（payload），输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串，如5266abfdc。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt; font-weight:600; font-style:italic;\">Optional Head：</span><span style=\" font-size:11pt;\">可选头部，输入限定为由0-9 a-f A-F组成的字符串，即十六进制数据字符串。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.textBrowser_Saveinpcap.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">以PCAP形式保存说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">该功能用于将已经生成的数据包存到本地PCAP文件中，保存方式为append模式，即在本地PCAP文件末尾插入需要保存的数据包，不影响PCAP文件原本的数据。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   点击菜单栏的Save in PCAP，在下拉菜单中选择Save..，弹出Save in PCAP对话框，点击...按钮后可选择本地文件，选择后输入框出现文件地址，点击Append按钮即可插入需要保存的数据包。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   保存成功后，出现Append Successfully！字样。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   </span><span style=\" font-size:12pt; font-weight:600;\">注意</span><span style=\" font-size:12pt;\">：该功能只适用于通过发包界面Generate Packet后，保存生成的数据包。</span></p></body></html>"))
        self.textBrowser_readfrompcap.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">从PCAP文件读取说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">该功能用于读取本地PCAP文件中的数据包，进行一定程度的包过滤，并支持发送从本地PCAP文件中选中的数据包。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   1、点击菜单栏的Read from PCAP，在下拉菜单中选择Read..，弹出Read from PCAP对话框。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   2、点击File后面的...按钮后可选择要读取的本地PCAP文件，选择后输入框出现文件地址。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   3、下面的Filter各项是过滤选项，选中想要过滤的选项，有的需要填入过滤条件，过滤条件的格式和发包界面需要的格式相同。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   4、过滤选项完成后，点击Filter按钮，下方框中出现选中PCAP文件中满足过滤要求的数据包的序号和摘要。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   5、在下方输入要发送的数据包的序号（过滤后输入框中出现的序号），点击右侧箭头按钮，右端输入框中出现数据包完整格式，点击Send Packet即可发送。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   6、发送成功后，出现Send a packet！字样。</span></p></body></html>"))
        self.textBrowser_Tools.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">密码工具说明</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">  </span><span style=\" font-size:12pt;\">这是自主增加的内容，方便对数据包的数据进行各种简单密码处理。所有出现的加密数据均可通过复制成为报文数据。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   1、AES加密</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   进行AES加密处理。打开对话框后，填入AES加密需要的密钥和IV，上方的框中输入要加密的数据，点击加密按钮，下方即出现加密后的数据。下方的框中输入加密后的数据，点击解密按钮，上方即出现解密的数据。点击清零按钮，数据框内容清零</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   </span><span style=\" font-size:12pt; font-weight:600;\">注意</span><span style=\" font-size:12pt;\">：（1）默认使用CBC模式，不可更改。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">         （2）密钥必须是16，24，32byte的数字int格式数据。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">         （3）IV必须是16byte的数字int格式数据。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   </span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   2、Hash加密(SHA256)</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   对数据Hash处理，使用的算法是SHA256算法。在左侧框中输入数据，点击哈希加密按钮，右侧即出现哈希结果。点击清零按钮，数据框内容清零</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   3、RSA密钥</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   用于产生进行RSA加密和数字签名的公钥和私钥文件。输入要保存为的文件名，点击创建密钥文件按钮，会在程序文件目录下生成名为“...-public.pem”的公钥文件和名为“...-private.pem”的私钥文件。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   </span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   4、RSA加密</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   用于通过RSA密钥生成的公私钥文件进行加密解密。根据要求选择本地文件中的公私钥文件。上方的框中为要加密的数据，点击加密后右侧出现加密后数据。下方的框中为加密后的数据，点击解密后上方出现解密后的数据，点击清零按钮，数据框内容清零。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   5、RSA数字签名</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   用于通过RSA密钥生成的公私钥文件进行数字签名和签名验证。根据要求选择本地文件中的公私钥文件。左侧框中为要签名的数据，点击转换后右侧出现数字签名。在左侧存在签名前的数据且右侧存在数字签名时，点击检查按钮，判断签名正确性。若正确右侧框中出现Signature Check correct!字样，错误出现Signature Check wrong!字样，点击清零按钮，数据框内容清零。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   </span><span style=\" font-size:12pt; font-weight:600;\">注意</span><span style=\" font-size:12pt;\">：检查按钮必须同时有签名前的数据和数字签名才能起作用。</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   </span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   6、16进制与字符串转换</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:12pt;\">   用于对数据进行十六进制和字符串之间的相互转换。上方的框输入十六进制数据，点击16进制到字符串按钮，下方出现对应的字符串数据。下方输入字符串数据，点击字符串转16进制按钮，上方出现对应的十六进制数据。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:12pt;\"><br /></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.textBrowser.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">版本信息：</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">Package Sender 1.0</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">开发人员：</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">吴怡琳（516021910334）前端GUI</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">徐民凯（）后端</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:16pt; font-weight:600;\">前后端连接与逻辑部分为两人共同完成。</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:16pt;\"><br /></p></body></html>"))
        self.menu_F.setTitle(_translate("MainWindow", "文件(F)"))
        self.menu_P.setTitle(_translate("MainWindow", "协议(P)"))
        self.menu_T.setTitle(_translate("MainWindow", "工具(T)"))
        self.menu_H.setTitle(_translate("MainWindow", "帮助(H)"))
        self.menuFile.setTitle(_translate("MainWindow", "文件"))
        self.menuProtocols.setTitle(_translate("MainWindow", "协议"))
        self.menuTools.setTitle(_translate("MainWindow", "工具"))
        self.actionSave_in_PCAP.setText(_translate("MainWindow", "以PCAP形式保存"))
        self.actionRead_from_PCAP.setText(_translate("MainWindow", "从PCAP文件读取"))
        self.actionEXIT.setText(_translate("MainWindow", "退出"))
        self.actionIP.setText(_translate("MainWindow", "IP"))
        self.actionTCP.setText(_translate("MainWindow", "TCP"))
        self.actionUDP.setText(_translate("MainWindow", "UDP"))
        self.actionARP.setText(_translate("MainWindow", "ARP"))
        self.actionICMP.setText(_translate("MainWindow", "ICMP"))
        self.actionAES_encryption.setText(_translate("MainWindow", "AES加密"))
        self.actionHash_SHA256.setText(_translate("MainWindow", "Hash_SHA256加密"))
        self.actionRSA_key_gen.setText(_translate("MainWindow", "RSA密钥"))
        self.actionRSA_encryption.setText(_translate("MainWindow", "RSA加密"))
        self.actionSignature_by_RSA.setText(_translate("MainWindow", "RSA数字签名"))
        self.actionHEX_input_and_output.setText(_translate("MainWindow", "16进制与字符串转换"))
        self.actionSave_in_PCAP_2.setText(_translate("MainWindow", "以PCAP形式保存"))
        self.actionRead_from_PCAP_2.setText(_translate("MainWindow", "从PCAP文件读取"))
        self.actionIP_2.setText(_translate("MainWindow", "IP"))
        self.actionTCP_2.setText(_translate("MainWindow", "TCP"))
        self.actionUDP_2.setText(_translate("MainWindow", "UDP"))
        self.actionARP_2.setText(_translate("MainWindow", "ARP"))
        self.actionICMP_2.setText(_translate("MainWindow", "ICMP"))
        self.actionAES_encryption_2.setText(_translate("MainWindow", "AES加密"))
        self.actionHash_SHA256_2.setText(_translate("MainWindow", "Hash_SHA256加密"))
        self.actionRSA_key_gen_2.setText(_translate("MainWindow", "RSA密钥"))
        self.actionRSA_encryption_2.setText(_translate("MainWindow", "RSA加密"))
        self.actionSignature_by_RSA_2.setText(_translate("MainWindow", "RSA数字签名"))
        self.actionHEX_input_and_output_2.setText(_translate("MainWindow", "16进制与字符串转换"))
        self.actionTools.setText(_translate("MainWindow","加密工具"))
        self.actionDetails.setText(_translate("MainWindow", "详情"))


