import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

def send_email():
    # Email configuration
    sender_email = "ha.lowkey.05.ck@gmail.com"
    sender_password = "iyne grhs iypl nkii"
    receiver_email = "ftd10622380@dseu.ac.in"
    subject = "PCAP File Attached"

    # Create a message object
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Add body text (optional)
    body = "Hello, attached is the PCAP file you requested."
    message.attach(MIMEText(body, "plain"))

    # Attach the PCAP file
    pcap_file_path = "sniffed_packets.cap"
    with open(pcap_file_path, "rb") as file:
        pcap_attachment = MIMEApplication(file.read())
        pcap_attachment["Content-Disposition"] = f"attachment; filename=sniffed_packets.cap"
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

if __name__ == "__main__":
    send_email()
