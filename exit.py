# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'exit.ui'
#
# Created: Fri Dec 14 20:36:15 2018
#      by: PyQt5 UI code generator 5.3.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_exit(object):
    def setupUi(self, exit):
        exit.setObjectName("exit")
        exit.resize(470, 178)
        self.pushButton = QtWidgets.QPushButton(exit)
        self.pushButton.setGeometry(QtCore.QRect(20, 100, 112, 34))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(exit)
        self.pushButton_2.setGeometry(QtCore.QRect(170, 100, 112, 34))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(exit)
        self.pushButton_3.setGeometry(QtCore.QRect(320, 100, 112, 34))
        self.pushButton_3.setObjectName("pushButton_3")
        self.label = QtWidgets.QLabel(exit)
        self.label.setGeometry(QtCore.QRect(60, 30, 391, 51))
        self.label.setObjectName("label")

        self.retranslateUi(exit)
        self.pushButton_3.clicked.connect(exit.close)
        QtCore.QMetaObject.connectSlotsByName(exit)

    def retranslateUi(self, exit):
        _translate = QtCore.QCoreApplication.translate
        exit.setWindowTitle(_translate("exit", "Form"))
        self.pushButton.setText(_translate("exit", "Save "))
        self.pushButton_2.setText(_translate("exit", "Not Save"))
        self.pushButton_3.setText(_translate("exit", "Cancel"))
        self.label.setText(_translate("exit", "Warning:You haven\'t saved the package!"))

