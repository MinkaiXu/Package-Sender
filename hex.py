# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'hex.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!
from PacketProcess import hexinput,hexoutput
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_hex(object):
    def setupUi(self, hex):
        hex.setObjectName("hex")
        hex.resize(802, 482)
        self.hexdata = QtWidgets.QTextEdit(hex)
        self.hexdata.setGeometry(QtCore.QRect(60,60,481,141))#20, 60, 321, 391
        self.hexdata.setObjectName("hexdata")
        self.hexstrdata = QtWidgets.QTextEdit(hex)
        self.hexstrdata.setGeometry(QtCore.QRect(60, 270, 481, 141))#460, 60, 321, 391
        self.hexstrdata.setObjectName("hexstrdata")
        self.stringbutton = QtWidgets.QPushButton(hex)
        self.stringbutton.setGeometry(QtCore.QRect(570, 110, 180, 51))#350, 160, 101, 51
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        self.stringbutton.setFont(font)
        self.stringbutton.setObjectName("stringbutton")
        self.hexbutton = QtWidgets.QPushButton(hex)
        self.hexbutton.setGeometry(QtCore.QRect(570,320,180,51))#350, 270, 101, 51
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        self.hexbutton.setFont(font)
        self.hexbutton.setObjectName("hexbutton")
        self.clear = QtWidgets.QPushButton(hex)
        self.clear.setGeometry(QtCore.QRect(570, 217, 180, 51))  # 350, 270, 101, 51
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        self.clear.setFont(font)
        self.clear.setObjectName("clear")
        self.label = QtWidgets.QLabel(hex)
        self.label.setGeometry(QtCore.QRect(60,20,171,31))#20, 20, 211, 31
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(65)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_6 = QtWidgets.QLabel(hex)
        self.label_6.setGeometry(QtCore.QRect(60,220,171,31))#460, 20, 171, 31
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(65)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")

        self.retranslateUi(hex)
        QtCore.QMetaObject.connectSlotsByName(hex)

        #trigger written
        self.hexbutton.clicked.connect(self.fuc_hexdata)
        self.stringbutton.clicked.connect(self.fuc_strdata)
        self.clear.clicked.connect(self.hexdata.clear)
        self.clear.clicked.connect(self.hexstrdata.clear)

    def retranslateUi(self, hex):
        _translate = QtCore.QCoreApplication.translate
        hex.setWindowTitle(_translate("hex", "加密工具：字符串与16进制转换"))
        self.stringbutton.setText(_translate("hex", "16进制->字符串"))
        self.hexbutton.setText(_translate("hex", "字符串->16进制"))
        self.label.setText(_translate("hex", "16进制数据:"))
        self.label_6.setText(_translate("hex", "字符串数据:"))
        self.clear.setText(_translate("hex","清零"))

    def fuc_hexdata(self):
        if(self.hexstrdata.toPlainText() == ''):
            self.hexdata.append("No String data!")
        else:
            self.hexdata.setText(hexoutput(self.hexstrdata.toPlainText()))

    def fuc_strdata(self):
        if (self.hexdata.toPlainText() == ''):
            self.hexstrdata.append("No Hex data!")
        else:
            self.hexstrdata.setText(hexinput(self.hexdata.toPlainText()))
