import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from os.path import basename

mail_content = '''Hello,
This is a test mail using Python SMTP library.
'''

#The mail addresses and password; sender_address is fake
sender_address = 'pygame367@gmail.com'
sender_pass = 'pygame367emagyp'
receiver_address = 'maria-magdalena.barbieru@student.tuiasi.ro'

message = MIMEMultipart()
attach_file_name = 'client.tar'

#Setup the MIME
def setup_mime():
    message['From'] = sender_address
    message['To'] = receiver_address

    #The subject line
    message['Subject'] = 'A mail sent by Python'


#The body and the attachments for the mail
def setup_email_body():
    message.attach(MIMEText(mail_content, 'plain'))

    # Open the file as binary mode
    attach_file = open(attach_file_name, 'rb') 
    payload = MIMEBase('application', 'octate-stream')
    payload.set_payload((attach_file).read())

    #encode the attachment
    encoders.encode_base64(payload) 

    #add payload header with filename
    print(basename(attach_file_name))
    payload.add_header('Content-Disposition', 'attachment', filename=attach_file_name)
    message.attach(payload)

#Create SMTP session for sending the mail
def send_email():
    #use gmail with port
    session = smtplib.SMTP('smtp.gmail.com', 587) 
    
    #enable security
    session.starttls() 

    print(sender_address + ", " + sender_pass)

    #login with mail_id and password
    session.login(sender_address, sender_pass) 
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()
    print('Mail Sent')


if __name__ == "__main__":
    setup_mime()
    setup_email_body()
    send_email()

