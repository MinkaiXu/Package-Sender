# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'savefile.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_saveInFile(object):
    def setupUi(self, saveInFile):
        saveInFile.setObjectName("saveInFile")
        saveInFile.resize(615, 250)
        self.label = QtWidgets.QLabel(saveInFile)
        self.label.setGeometry(QtCore.QRect(20, 60, 141, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(saveInFile)
        self.lineEdit.setGeometry(QtCore.QRect(160, 70, 380, 31))
        self.lineEdit.setObjectName("lineEdit")
        self.filebrowser = QtWidgets.QToolButton(saveInFile)
        self.filebrowser.setGeometry(QtCore.QRect(540, 70, 41, 31))
        self.filebrowser.setObjectName("filebrowser")
        self.fileappend = QtWidgets.QPushButton(saveInFile)
        self.fileappend.setGeometry(QtCore.QRect(250, 140, 131, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.fileappend.setFont(font)
        self.fileappend.setObjectName("fileappend")

        self.label_4 = QtWidgets.QLabel(saveInFile)
        self.label_4.setGeometry(QtCore.QRect(260, 200, 211, 30))
        # adding label
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(saveInFile)
        self.label_5.setGeometry(QtCore.QRect(260, 200, 211, 30))
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_4")
        self.label_6 = QtWidgets.QLabel(saveInFile)
        self.label_6.setGeometry(QtCore.QRect(250, 200, 211, 30))
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_4")

        self.retranslateUi(saveInFile)
        QtCore.QMetaObject.connectSlotsByName(saveInFile)

        # trigger written
        self.filename = ''
        self.filebrowser.clicked.connect(self.seekfile)

    def retranslateUi(self, saveInFile):
        _translate = QtCore.QCoreApplication.translate
        saveInFile.setWindowTitle(_translate("saveInFile", "以PCAP形式保存"))
        self.label.setText(_translate("saveInFile", "选取文件"))
        self.filebrowser.setText(_translate("saveInFile", "..."))
        self.fileappend.setText(_translate("saveInFile", "保存"))
        self.label_4.setText(_translate("saveInFile", "保存成功!"))
        self.label_5.setText(_translate("saveInFile", "无数据包!"))
        self.label_6.setText(_translate("saveInFile", "无指定文件!"))

        #setting written
        self.label_4.setVisible(False)
        self.label_5.setVisible(False)
        self.label_6.setVisible(False)

    #functions written
    def seekfile(self):
        self.filename,_ = QtWidgets.QFileDialog.getOpenFileName(None,
                                                           "选择保存文件",
                                                           "",
                                                           "All files(*)")
        self.lineEdit.setText(self.filename)
        self.label_4.setVisible(False)
        self.label_5.setVisible(False)
        self.label_6.setVisible(False)


