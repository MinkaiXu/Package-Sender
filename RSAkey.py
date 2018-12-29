# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'rsakey.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!
from Cryp import *
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_rsakeygen(object):
    def setupUi(self, rsakeygen):
        rsakeygen.setObjectName("rsakeygen")
        rsakeygen.resize(750, 280)
        self.rsakeyfilename = QtWidgets.QLineEdit(rsakeygen)
        self.rsakeyfilename.setGeometry(QtCore.QRect(150, 120, 480, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.rsakeyfilename.setFont(font)
        self.rsakeyfilename.setObjectName("rsakeyfilename")
        self.label = QtWidgets.QLabel(rsakeygen)
        self.label.setGeometry(QtCore.QRect(30, 130, 111, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.genkeyfile = QtWidgets.QPushButton(rsakeygen)
        self.genkeyfile.setGeometry(QtCore.QRect(160, 180, 291, 41))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(12)
        self.genkeyfile.setFont(font)
        self.genkeyfile.setObjectName("genkeyfile")
        self.label_2 = QtWidgets.QLabel(rsakeygen)
        self.label_2.setGeometry(QtCore.QRect(40, 10, 72, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        font.setItalic(True)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(rsakeygen)
        self.label_3.setGeometry(QtCore.QRect(40, 40, 700, 71))
        font = QtGui.QFont()
        font.setFamily("楷体")
        font.setPointSize(12)
        font.setItalic(True)
        self.label_3.setFont(font)
        self.label_3.setTextFormat(QtCore.Qt.PlainText)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(rsakeygen)
        self.label_4.setGeometry(QtCore.QRect(210, 240, 211, 21))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(12)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")

        #adding
        self.label_5 = QtWidgets.QLabel(rsakeygen)
        self.label_5.setGeometry(QtCore.QRect(230, 240, 211, 21))
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")

        self.retranslateUi(rsakeygen)
        QtCore.QMetaObject.connectSlotsByName(rsakeygen)

        #trigger written
        self.genkeyfile.clicked.connect(self.generate_key_file)

    def retranslateUi(self, rsakeygen):
        _translate = QtCore.QCoreApplication.translate
        rsakeygen.setWindowTitle(_translate("rsakeygen", "加密工具：创建保存RSA密钥的文件"))
        self.label.setText(_translate("rsakeygen", "文件名:"))
        self.genkeyfile.setText(_translate("rsakeygen", "创建密钥文件"))
        self.label_2.setText(_translate("rsakeygen", "注意:"))
        self.label_3.setText(_translate("rsakeygen", "请在下面的输入框内输入文件名，产生的扩展名为xx.pem，存储在\n"
" 本程序所在文件夹下，用于存放生成RSA算法所需的公钥和私钥"))

        self.label_4.setText(_translate("rsakeygen", "创建成功！"))
        self.label_5.setText(_translate("rsakeygen", "为输入文件名！"))

        #settings written
        self.label_4.setVisible(False)
        self.label_5.setVisible(False)

    #function written
    def generate_key_file(self):
        if(self.rsakeyfilename.text() == ''):
            self.label_4.setVisible(False)
            self.label_5.setVisible(True)
        else:
            RSAkey(self.rsakeyfilename.text())
            self.label_4.setVisible(True)
            self.label_5.setVisible(False)
