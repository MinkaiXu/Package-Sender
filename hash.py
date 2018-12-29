# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'hash.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!
from Cryp import *
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_hash(object):
    def setupUi(self, hash):
        hash.setObjectName("hash")
        #hash.resize(775, 367)
        hash.resize(721, 579)
        self.hashdata = QtWidgets.QTextEdit(hash)
        #self.hashdata.setGeometry(QtCore.QRect(20, 40, 741, 131))
        self.hashdata.setGeometry(QtCore.QRect(20, 110, 271, 371))
        self.hashdata.setObjectName("hashdata")
        self.label = QtWidgets.QLabel(hash)
        #self.label.setGeometry(QtCore.QRect(20, 10, 211, 31))
        self.label.setGeometry(QtCore.QRect(40, 70, 281, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.hashresult = QtWidgets.QTextEdit(hash)
        #self.hashresult.setGeometry(QtCore.QRect(20, 270, 741, 71))
        self.hashresult.setGeometry(QtCore.QRect(450, 110, 250, 371))
        self.hashresult.setObjectName("hashresult")
        self.label_2 = QtWidgets.QLabel(hash)
        self.label_2.setGeometry(QtCore.QRect(470, 70, 281, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.hashbutton = QtWidgets.QPushButton(hash)
        #self.hashbutton.setGeometry(QtCore.QRect(340, 180, 81, 61))
        self.hashbutton.setGeometry(QtCore.QRect(310, 250, 131, 81))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(14)
        font.setBold(False)
        font.setWeight(50)
        self.hashbutton.setFont(font)
        self.hashbutton.setObjectName("hashbutton")
        self.clear = QtWidgets.QPushButton(hash)
        self.clear.setGeometry(QtCore.QRect(310, 350, 131, 81))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(50)
        self.clear.setFont(font)
        self.clear.setObjectName("clear")
        self.retranslateUi(hash)
        QtCore.QMetaObject.connectSlotsByName(hash)

        #trigger written
        self.hashbutton.clicked.connect(self.fuc_hash)
        self.clear.clicked.connect(self.hashdata.clear)
        self.clear.clicked.connect(self.hashresult.clear)

    def retranslateUi(self, hash):
        _translate = QtCore.QCoreApplication.translate
        hash.setWindowTitle(_translate("hash", "加密工具：Hash_SHA256加密"))
        self.label.setText(_translate("hash", "未加密数据:"))
        self.label_2.setText(_translate("hash", "加密的数据:"))
        self.hashbutton.setText(_translate("hash", "哈希\n"
"加密"))
        self.clear.setText(_translate("hash","清零"))

    def fuc_hash(self):
        if(self.hashdata.toPlainText() == ''):
            self.hashresult.append("No data to be hashed!")
        else:
            self.hashresult.setText(Hash_SHA256(self.hashdata.toPlainText()))
