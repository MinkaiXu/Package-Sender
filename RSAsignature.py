# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'rsasig.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!
from Cryp import *
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_rsasig(object):
    def setupUi(self, rsasig):
        rsasig.setObjectName("rsasig")
        rsasig.resize(767, 535)
        self.rsasigbutton = QtWidgets.QPushButton(rsasig)
        self.rsasigbutton.setGeometry(QtCore.QRect(120, 480, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.rsasigbutton.setFont(font)
        self.rsasigbutton.setObjectName("rsasigbutton")
        self.label_6 = QtWidgets.QLabel(rsasig)
        self.label_6.setGeometry(QtCore.QRect(440, 105, 201, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.rsacheckdata = QtWidgets.QTextEdit(rsasig)
        self.rsacheckdata.setGeometry(QtCore.QRect(400, 140, 341, 321))
        self.rsacheckdata.setObjectName("rsacheckdata")
        self.label_3 = QtWidgets.QLabel(rsasig)
        self.label_3.setGeometry(QtCore.QRect(30, 70, 200, 31))#30, 50, 121, 31
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.rsacheckbutton = QtWidgets.QPushButton(rsasig)
        self.rsacheckbutton.setGeometry(QtCore.QRect(510, 480, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.rsacheckbutton.setFont(font)
        self.rsacheckbutton.setObjectName("rsacheckbutton")
        self.clear=QtWidgets.QPushButton(rsasig)
        self.clear.setGeometry(QtCore.QRect(315, 480, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.clear.setFont(font)
        self.clear.setObjectName("clear")
        self.rsasigdata = QtWidgets.QTextEdit(rsasig)
        self.rsasigdata.setGeometry(QtCore.QRect(20, 140, 341, 321))
        self.rsasigdata.setObjectName("rsasigdata")
        self.rsaprikeyfilechoose = QtWidgets.QPushButton(rsasig)
        self.rsaprikeyfilechoose.setGeometry(QtCore.QRect(710, 70, 31, 31))
        self.rsaprikeyfilechoose.setObjectName("rsaprikeyfilechoose")
        self.rsaprikeyfile = QtWidgets.QLineEdit(rsasig)
        self.rsaprikeyfile.setGeometry(QtCore.QRect(170, 70, 530, 31))#160, 50, 551, 31
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.rsaprikeyfile.setFont(font)
        self.rsaprikeyfile.setObjectName("rsaprikeyfile")
        self.rsapubkeyfilechoose = QtWidgets.QPushButton(rsasig)
        self.rsapubkeyfilechoose.setGeometry(QtCore.QRect(710, 23, 31, 31))#710, 10, 31, 31
        self.rsapubkeyfilechoose.setObjectName("rsapubkeyfilechoose")
        self.label = QtWidgets.QLabel(rsasig)
        self.label.setGeometry(QtCore.QRect(30, 30, 180, 31))#30, 10, 131, 31
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(rsasig)
        self.label_2.setGeometry(QtCore.QRect(30, 105, 261, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.rsapubkeyfile = QtWidgets.QLineEdit(rsasig)
        self.rsapubkeyfile.setGeometry(QtCore.QRect(170, 30, 530, 31))#160, 10, 551, 31
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.rsapubkeyfile.setFont(font)
        self.rsapubkeyfile.setObjectName("rsapubkeyfile")

        self.retranslateUi(rsasig)
        QtCore.QMetaObject.connectSlotsByName(rsasig)

        # trigger written
        self.rsaprikeyfilechoose.clicked.connect(self.seekprikey)
        self.rsapubkeyfilechoose.clicked.connect(self.seekpubkey)
        self.rsasigbutton.clicked.connect(self.fuc_sig)
        self.rsacheckbutton.clicked.connect(self.fuc_check)
        self.clear.clicked.connect(self.rsasigdata.clear)
        self.clear.clicked.connect(self.rsacheckdata.clear)

    def retranslateUi(self, rsasig):
        _translate = QtCore.QCoreApplication.translate
        rsasig.setWindowTitle(_translate("rsasig", "加密工具：RSA数字签名"))
        self.rsasigbutton.setText(_translate("rsasig", "转换"))
        self.label_6.setText(_translate("rsasig", "签名:"))
        self.label_3.setText(_translate("rsasig", "私钥文件："))
        self.rsacheckbutton.setText(_translate("rsasig", "检查"))
        self.rsaprikeyfilechoose.setText(_translate("rsasig", "..."))
        self.rsapubkeyfilechoose.setText(_translate("rsasig", "..."))
        self.label.setText(_translate("rsasig", "公钥文件："))
        self.label_2.setText(_translate("rsasig", "数据:(16进制)"))
        self.clear.setText(_translate("rsasig","清零"))

    #functions written
    def seekprikey(self):
        self.prikeyfile,_ = QtWidgets.QFileDialog.getOpenFileName(None,
                                                           "选择私钥文件",
                                                           "",
                                                           "All files(*)")
        self.rsaprikeyfile.setText(self.prikeyfile)

    def seekpubkey(self):
        self.pubkeyfile,_ = QtWidgets.QFileDialog.getOpenFileName(None,
                                                           "选择公钥文件",
                                                           "",
                                                           "All files(*)")
        self.rsapubkeyfile.setText(self.pubkeyfile)

    def fuc_sig(self):
        try:
            if (self.rsaprikeyfile.text() == ''):
                self.rsacheckdata.append("No prikey!")
            elif (self.rsasigdata.toPlainText() == ''):
                self.rsacheckdata.append("No data")
            else:
                self.rsacheckdata.setText(RSA_sig(str(self.rsaprikeyfile.text()),
                                                     str(self.rsasigdata.toPlainText())))
        except:
            self.rsasigdata.setText("Notice:Must be hex input")

    def fuc_check(self):
        if (self.rsapubkeyfile.text() == ''):
            self.rsacheckdata.setText("No pubkey!")
        elif (self.rsasigdata.toPlainText() == ''):
            self.rsacheckdata.setText("No data")
        elif (self.rsacheckdata.toPlainText() == ''):
            self.rsacheckdata.setText("No Signature")
        else:
            flag = RSA_sig_check(str(self.rsapubkeyfile.text()),
                                   str(self.rsasigdata.toPlainText()),
                                   str(self.rsacheckdata.toPlainText()))
            if(flag):
                self.rsacheckdata.append("\n\n"+"Signature check correct!")
            else:
                self.rsacheckdata.append("\n\n" + "Signature check wrong!")
