# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'rsaencry.ui'
#
# Created by: PyQt5 UI code generator 5.7.1
#
# WARNING! All changes made in this file will be lost!
from Cryp import *
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_rsaencrypt(object):
    def setupUi(self, rsaencrypt):
        rsaencrypt.setObjectName("rsaencrypt")
        rsaencrypt.resize(767, 500)
        self.rsapubkeyfile = QtWidgets.QLineEdit(rsaencrypt)
        self.rsapubkeyfile.setGeometry(QtCore.QRect(170, 20, 530, 31))#(160,20,531,31)
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.rsapubkeyfile.setFont(font)
        self.rsapubkeyfile.setObjectName("rsapubkeyfile")
        self.label = QtWidgets.QLabel(rsaencrypt)
        self.label.setGeometry(QtCore.QRect(30, 20, 180, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.rsapubkeyfilechoose = QtWidgets.QPushButton(rsaencrypt)
        self.rsapubkeyfilechoose.setGeometry(QtCore.QRect(710, 20, 31, 31))
        self.rsapubkeyfilechoose.setObjectName("rsapubkeyfilechoose")
        self.rsaencry = QtWidgets.QPushButton(rsaencrypt)
        #self.rsaencry.setGeometry(QtCore.QRect(342, 220, 81, 51))
        self.rsaencry.setGeometry(QtCore.QRect(30, 180, 121, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(50)
        self.rsaencry.setFont(font)
        self.rsaencry.setObjectName("rsaencry")
        self.rsadataencrypted = QtWidgets.QTextEdit(rsaencrypt)
        #self.rsadataencrypted.setGeometry(QtCore.QRect(430, 130, 311, 351))
        self.rsadataencrypted.setGeometry(QtCore.QRect(220, 330, 481, 131))
        self.rsadataencrypted.setObjectName("rsadataencrypted")
        self.rsadata = QtWidgets.QTextEdit(rsaencrypt)
        #self.rsadata.setGeometry(QtCore.QRect(20, 130, 311, 351))
        self.rsadata.setGeometry(QtCore.QRect(220, 140, 481, 131))
        self.rsadata.setObjectName("rsadata")
        self.label_2 = QtWidgets.QLabel(rsaencrypt)
        #self.label_2.setGeometry(QtCore.QRect(20, 100, 211, 31))
        self.label_2.setGeometry(QtCore.QRect(270, 100, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.rsaclear=QtWidgets.QPushButton(rsaencrypt)
        self.rsaclear.setGeometry(QtCore.QRect(30,270,131,51))
        font=QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(50)
        self.rsaclear.setFont(font)
        self.rsadecry = QtWidgets.QPushButton(rsaencrypt)
        #self.rsadecry.setGeometry(QtCore.QRect(340, 310, 81, 51))
        self.rsadecry.setGeometry(QtCore.QRect(30, 360, 131, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(50)
        self.rsadecry.setFont(font)
        self.rsadecry.setObjectName("rsadecry")
        self.label_6 = QtWidgets.QLabel(rsaencrypt)
        #self.label_6.setGeometry(QtCore.QRect(430, 100, 171, 31))
        self.label_6.setGeometry(QtCore.QRect(270, 290, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.rsaprikeyfilechoose = QtWidgets.QPushButton(rsaencrypt)
        self.rsaprikeyfilechoose.setGeometry(QtCore.QRect(710, 60, 31, 31))
        self.rsaprikeyfilechoose.setObjectName("rsaprikeyfilechoose")
        self.label_3 = QtWidgets.QLabel(rsaencrypt)
        self.label_3.setGeometry(QtCore.QRect(30, 60, 200, 31))#(30,60,121,31)
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.rsaprikeyfile = QtWidgets.QLineEdit(rsaencrypt)
        self.rsaprikeyfile.setGeometry(QtCore.QRect(170, 60, 530, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.rsaprikeyfile.setFont(font)
        self.rsaprikeyfile.setObjectName("rsaprikeyfile")

        self.retranslateUi(rsaencrypt)
        QtCore.QMetaObject.connectSlotsByName(rsaencrypt)

        # trigger written
        self.rsaprikeyfilechoose.clicked.connect(self.seekprikey)
        self.rsapubkeyfilechoose.clicked.connect(self.seekpubkey)
        self.rsaencry.clicked.connect(self.fuc_encry)
        self.rsadecry.clicked.connect(self.fuc_decry)
        self.rsaclear.clicked.connect(self.rsadataencrypted.clear)
        self.rsaclear.clicked.connect(self.rsadata.clear)

    def retranslateUi(self, rsaencrypt):
        _translate = QtCore.QCoreApplication.translate
        rsaencrypt.setWindowTitle(_translate("rsaencrypt", "加密工具：RSA加密"))
        self.label.setText(_translate("rsaencrypt", "公钥文件："))
        self.rsapubkeyfilechoose.setText(_translate("rsaencrypt", "..."))
        self.rsaencry.setText(_translate("rsaencrypt", "加密"))
        self.label_2.setText(_translate("rsaencrypt", "未加密/解密后的数据:"))
        self.rsadecry.setText(_translate("rsaencrypt", "解密"))
        self.label_6.setText(_translate("rsaencrypt", "加密后/未解密的数据:"))
        self.rsaprikeyfilechoose.setText(_translate("rsaencrypt", "..."))
        self.label_3.setText(_translate("rsaencrypt", "私钥文件："))
        self.rsaclear.setText(_translate("rsaencrypt","清零"))
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

    def fuc_encry(self):
        try:
            if(self.rsapubkeyfile.text() == ''):
                self.rsadataencrypted.append("No pubkey!")
            elif(self.rsadata.toPlainText() == ''):
                self.rsadataencrypted.append("No data")
            else:
                self.rsadataencrypted.setText(PackContentRSA(str(self.rsapubkeyfile.text()),
                                                         str(self.rsadata.toPlainText())))
        except:
            self.rsadata.setText("Please input hex data!"+"\n"+\
                                 "You can use Hex Input and Output tools.")

    def fuc_decry(self):
        if (self.rsaprikeyfile.text() == ''):
            self.rsadata.append("No prikey!")
        elif (self.rsadataencrypted.toPlainText() == ''):
            self.rsadata.append("No data")
        else:
            self.rsadata.setText(PackContentRSAdecry(str(self.rsaprikeyfile.text()),
                                                     str(self.rsadataencrypted.toPlainText())))

