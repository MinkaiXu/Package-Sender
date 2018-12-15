import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from packagesend import *
from Savefile import *
from Readfile import *
from AES import *
from hash import *
from RSAkey import *
from RSAencryption import *
from RSAsignature import *
from hex import *
from exit import *
import SockIcmp,SockArp,SockUdp,SockTcp,SockIp,SockPcap

def appendfile():
    if (gui.packet == 0):
        save_in_file.label_4.setVisible(False)
        save_in_file.label_5.setVisible(True)
        save_in_file.label_6.setVisible(False)
    elif (save_in_file.filename == ''):
        save_in_file.label_4.setVisible(False)
        save_in_file.label_5.setVisible(False)
        save_in_file.label_6.setVisible(True)
    else:
        gui.packet.appendPCAP(save_in_file.filename)
        save_in_file.label_4.setVisible(True)
        save_in_file.label_5.setVisible(False)
        save_in_file.label_6.setVisible(False)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    #main window
    gui = Ui_MainWindow()
    mainwin = QtWidgets.QMainWindow()
    gui.setupUi(mainwin)

    #save in PCAP window
    save_in_file = Ui_saveInFile()
    save_in_file_dialog = QtWidgets.QDialog()
    save_in_file.setupUi(save_in_file_dialog)
    gui.actionSave_in_PCAP.triggered.connect(save_in_file_dialog.show)
    save_in_file.fileappend.clicked.connect(appendfile)


    #read from PCAP window
    read_from_pcap = Ui_readpcap()
    read_from_pcap_widget = QtWidgets.QWidget()
    read_from_pcap.setupUi(read_from_pcap_widget)
    gui.actionRead_from_PCAP.triggered.connect(read_from_pcap_widget.show)

    # exit window
    exit_all = Ui_exit()
    exit_all_widget = QtWidgets.QWidget()
    exit_all.setupUi(exit_all_widget)
    gui.actionEXIT.triggered.connect(exit_all_widget.show)
    exit_all.pushButton.clicked.connect(save_in_file_dialog.show)
    exit_all.pushButton_2.clicked.connect(mainwin.close)
    exit_all.pushButton_2.clicked.connect(exit_all_widget.close)

    #AES encryption window
    aes_encryption = Ui_aes()
    aes_encryption_widget = QtWidgets.QWidget()
    aes_encryption.setupUi(aes_encryption_widget)
    gui.actionAES_encryption.triggered.connect(aes_encryption_widget.show)

    #Hash(SHA256) window
    hash_sha256 = Ui_hash()
    hash_sha256_widget = QtWidgets.QWidget()
    hash_sha256.setupUi(hash_sha256_widget)
    gui.actionHash_SHA256.triggered.connect(hash_sha256_widget.show)

    #RSA key gen window
    rsa_key_gen = Ui_rsakeygen()
    rsa_key_gen_widget = QtWidgets.QWidget()
    rsa_key_gen.setupUi(rsa_key_gen_widget)
    gui.actionRSA_key_gen.triggered.connect(rsa_key_gen_widget.show)

    # RSA encryption window
    rsa_encryption = Ui_rsaencrypt()
    rsa_encryption_widget = QtWidgets.QWidget()
    rsa_encryption.setupUi(rsa_encryption_widget)
    gui.actionRSA_encryption.triggered.connect(rsa_encryption_widget.show)

    # Signature by RSA window
    rsa_sig = Ui_rsasig()
    rsa_sig_widget = QtWidgets.QWidget()
    rsa_sig.setupUi(rsa_sig_widget)
    gui.actionSignature_by_RSA.triggered.connect(rsa_sig_widget.show)

    # Hex Input and Output window
    hex = Ui_hex()
    hex_widget = QtWidgets.QWidget()
    hex.setupUi(hex_widget)
    gui.actionHEX_input_and_output.triggered.connect(hex_widget.show)



    mainwin.show()
    sys.exit(app.exec_())
