# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'AES.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!
from Cryp import *
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_aes(object):
    def setupUi(self, aes):
        aes.setObjectName("aes")
        aes.resize(761, 520)
        self.label = QtWidgets.QLabel(aes)
        #self.label.setGeometry(QtCore.QRect(20, 180, 211, 31))
        self.label.setGeometry(QtCore.QRect(200, 170, 491, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(65)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.aesdata = QtWidgets.QTextEdit(aes)
       # self.aesdata.setGeometry(QtCore.QRect(20, 210, 311, 291))
        self.aesdata.setGeometry(QtCore.QRect(180, 210, 501, 121))
        self.aesdata.setObjectName("aesdata")
        self.label_2 = QtWidgets.QLabel(aes)
        #self.label_2.setGeometry(QtCore.QRect(20, 10, 101, 31))
        self.label_2.setGeometry(QtCore.QRect(25, 50, 111, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(65)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(aes)
       # self.label_3.setGeometry(QtCore.QRect(120, 15, 241, 21))
        self.label_3.setGeometry(QtCore.QRect(150, 23, 361, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
       # font.setItalic(True)
        font.setBold(False)
        font.setWeight(65)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.aeskey = QtWidgets.QTextEdit(aes)
        #self.aeskey.setGeometry(QtCore.QRect(20, 40, 721, 51))
        self.aeskey.setGeometry(QtCore.QRect(140, 50, 581, 41))
        self.aeskey.setObjectName("aeskey")
        self.label_4 = QtWidgets.QLabel(aes)
        #self.label_4.setGeometry(QtCore.QRect(20, 95, 101, 31))
        self.label_4.setGeometry(QtCore.QRect(50, 120, 91, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(65)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(aes)
       # self.label_5.setGeometry(QtCore.QRect(60, 100, 351, 21))
        self.label_5.setGeometry(QtCore.QRect(150, 90, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
        #font.setItalic(True)
        font.setBold(False)
        font.setWeight(65)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.aesiv = QtWidgets.QTextEdit(aes)
        #self.aesiv.setGeometry(QtCore.QRect(20, 130, 721, 31))
        self.aesiv.setGeometry(QtCore.QRect(140, 120, 580, 41))
        self.aesiv.setObjectName("aesiv")
        self.aesdataencrypted = QtWidgets.QTextEdit(aes)
        #self.aesdataencrypted.setGeometry(QtCore.QRect(430, 210, 311, 291))
        self.aesdataencrypted.setGeometry(QtCore.QRect(180, 380, 501, 121))
        self.aesdataencrypted.setObjectName("aesdataencrypted")
        self.label_6 = QtWidgets.QLabel(aes)
        #self.label_6.setGeometry(QtCore.QRect(430, 180, 171, 31))
        self.label_6.setGeometry(QtCore.QRect(200, 340, 491, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(65)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.encry = QtWidgets.QPushButton(aes)
        #self.encry.setGeometry(QtCore.QRect(342, 280, 81, 51))
        self.encry.setGeometry(QtCore.QRect(30, 220, 111, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.encry.setFont(font)
        self.encry.setObjectName("encry")
        self.clear = QtWidgets.QPushButton(aes)
        self.clear.setGeometry(QtCore.QRect(30, 310, 111, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(50)
        self.clear.setFont(font)
        self.clear.setObjectName("clear")
        self.decry = QtWidgets.QPushButton(aes)
        #self.decry.setGeometry(QtCore.QRect(340, 370, 81, 51))
        self.decry.setGeometry(QtCore.QRect(30, 400, 111, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.decry.setFont(font)
        self.decry.setObjectName("decry")

        self.retranslateUi(aes)
        QtCore.QMetaObject.connectSlotsByName(aes)

        #trigger written
        self.encry.clicked.connect(self.fuc_encry)
        self.decry.clicked.connect(self.fuc_decry)
        self.clear.clicked.connect(self.aesdata.clear)
        self.clear.clicked.connect(self.aesdataencrypted.clear)

    def retranslateUi(self, aes):
        _translate = QtCore.QCoreApplication.translate
        aes.setWindowTitle(_translate("aes", "加密工具：AES加密"))
        self.label.setText(_translate("aes", "未加密 / 解密后的数据:"))
        self.label_2.setText(_translate("aes", "AES密钥:"))
        self.label_3.setText(_translate("aes", "(必须是 16,24,32 字节的16进制数据)"))
        self.label_4.setText(_translate("aes", "IV:"))
        self.label_5.setText(_translate("aes", "(CBC模式，IV必须是16字节的16进制数据)"))
        self.label_6.setText(_translate("aes", "加密后 / 未解密的数据:"))
        self.encry.setText(_translate("aes", "加密"))
        self.decry.setText(_translate("aes", "解密"))
        self.clear.setText(_translate("aes","清零"))
    #function written
    def fuc_encry(self):
        try:
            if(self.aeskey.toPlainText() == ''):
                self.aesdataencrypted.append("Empty key!")
            elif(self.aesiv.toPlainText() == ''):
                self.aesdataencrypted.append("Empty IV!")
            elif(self.aesdata.toPlainText() == ''):
                self.aesdataencrypted.append("Empty Input data!")
            else:
                try:
                    self.aesdataencrypted.setText(AES_encrypt(self.aesdata.toPlainText(),
                                                             self.aeskey.toPlainText(),
                                                             self.aesiv.toPlainText()))
                except:
                    self.aesdataencrypted.setText("The length of Key or IV is invalid!\n"+\
                                                  "or\nInput is not hex")
        except:
            self.aesdata.setText("Key and IV must be hex!")

    def fuc_decry(self):
        try:
            if (self.aeskey.toPlainText() == ''):
                self.aesdata.append("Empty key!")
            elif (self.aesiv.toPlainText() == ''):
                self.aesdata.append("Empty IV!")
            elif (self.aesdataencrypted.toPlainText() == ''):
                self.aesdata.append("Empty Input data!")
            else:
                try:
                    self.aesdata.setText(AES_decrypt(self.aesdataencrypted.toPlainText(),
                                                    self.aeskey.toPlainText(),
                                                    self.aesiv.toPlainText()))
                except:
                    self.aesdata.setText("The length of Key or IV is invalid!")
        except:
            self.aesdataencrypted.setText("Key and IV must be hex!")