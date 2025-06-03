import abc
import struct
import socket
import time
import threading
import pprint
import queue

VERBOSE:bool = False
SERVER_IP:str= "10.147.85.98"
OWN_IP:str = "10.147.85.205"
SERVER_PORT:int= 12345
class clientImpl():
    def __init__(self, nickname: str):
            self.nickname:str = nickname

            self.LATEST_LIST_PRINTED = True
            self.udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind((OWN_IP, 0))
            self.ip_addr, self.port = self.udp_socket.getsockname()
            print(f"UDP socket bound to {self.ip_addr}:{self.port}")

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setblocking(True)
            self.tracked_users_udp_socket:dict[str, tuple[str, int]] = {}
            self.tracked_user_tcp_socket:dict[str, socket.socket] = {}
            self.broadcast_queue = queue.Queue()

    def send(self, nickname: str, msg: str):
        if(nickname.lower() == "broadcast"):

            print("broadcasting is not supported yet")
            return
        if nickname not in self.tracked_user_tcp_socket:
            if nickname not in self.tracked_users_udp_socket.keys():
                print("User was not found!")
                return
            print(f"No TCP connection to {nickname}. Attempting to connect via tcp")
            # Versuche TCP-Verbindung aufzubauen
            peer_ip, peer_port = self.tracked_users_udp_socket[nickname]
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.bind((self.ip_addr, 0))
            new_socket.setblocking(True)
            new_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            new_udp_socket.setblocking(True)

            try:
                data = build_connection_request(new_socket.getsockname()[0], new_socket.getsockname()[1])
                new_udp_socket.sendto(data, (peer_ip, peer_port))
                print(f"Send request for getting TCP Port to {(peer_ip, peer_port)}")
                new_socket.listen()
                new_socket, addr = new_socket.accept()
                data = new_socket.recv(1024)
                print("Data recieved")
                msg_id, payload = parse_packet(data)
                received_nickname, valid = parse_peer_connecting(payload)
                if not valid or received_nickname != nickname:
                    print(f"valid:{valid}")
                    print(f"recieved_nickname:{received_nickname}")
                    print("Invalid peer response, aborting.")
                    return
                print(f"Established TCP connection to {nickname} {addr}")
                self.tracked_user_tcp_socket[nickname] = new_socket

                peer_return_packet = build_peer_connecting(self.nickname)
                new_socket.send(peer_return_packet)
            except Exception as e:
                print(f"Failed to connect to {nickname}: {e}")
                print(f"my ip_addr: {self.ip_addr} my port: {self.port}")
                return

        try:
            packet = build_message_to_peer(msg)
            self.tracked_user_tcp_socket[nickname].send(packet)
            print(f"Send message to {nickname}: {msg}")
        except Exception as e:
            print(f"Send failed, retrying TCP connect to {nickname}: {e}")
            self.tracked_user_tcp_socket.pop(nickname)

    def connect_to_server(self):
        while True:
            try:
                print("Connecting to Server..")

                self.server_socket.connect((SERVER_IP, SERVER_PORT))
                break
            except socket.timeout:
                print("Timeout")
                time.sleep(5)
            except socket.error as e:
                print(f"Error: {e}")
                time.sleep(5)

        print("succeeded")
        nicknamelen = len(self.nickname)
        nickname_encoded = self.nickname.encode("utf-8")

        format_string = f">B{nicknamelen}s4sH"
        print(f"format_string: {format_string}, nicknamelen:{nicknamelen}, nickname_encoded:{nickname_encoded}, self.ip_addr:{self.ip_addr}, self.port:{self.port}")
        ip_bytes = socket.inet_aton(self.ip_addr)
        msg_id = 0x01
        payload = struct.pack(format_string, nicknamelen, nickname_encoded, ip_bytes, self.port)
        package = build_packet(msg_id, payload)
        self.server_socket.send(package)
        try:
            return_val = self.server_socket.recv(1024).decode("utf-8")
            if (return_val == str(0x01)):
                print("Server LogIn successfull")
        except socket.error as e:
            pass
            print("Login unnsuccessful")
            print("retrying")

    def recieve(self):
        index = 0
        while True:
            data = bytes()
            if len(self.tracked_user_tcp_socket) == 0:
                continue
            try:
                data = self.tracked_user_tcp_socket[list(self.tracked_user_tcp_socket.keys())[index]].recv(1024)
                index = (index + 1) % len(self.tracked_user_tcp_socket)
            except socket.error as e:
                index = (index + 1) % len(self.tracked_user_tcp_socket)
                continue

            message_id, payload_length = struct.unpack(">BH", data[:3])
            payload = data[3:3 + payload_length]
            output_message = f"[{list(self.tracked_users_udp_socket.keys())[index]}]:{payload.decode('utf-8')}"
            print(output_message)

    def listen_for_UDP_request(self):
        """
        supposed to be run as an independent Thread to initiate incoming connection.
        """
        #recieve request
        ip, port =  (0, "")
        while True:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                msg_id, data = parse_packet(data)
                ip, port = parse_connection_request(data)
                break
            except socket.error as e:
                time.sleep(1)
                continue
        threading.Thread(target=self.listen_for_UDP_request, daemon=True).start()
        #response
        print(f"Recieved incoming connection Request from: {ip}:{port}")
        while True:
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.setblocking(True)
            contin:bool = False
            for current_try in range(0,3):
                try:
                    print("trying to accept connection...")
                    print(f"IP:{ip} port: {port}")
                    new_socket.connect((ip, port))
                    print("Connection succeded")
                    break
                except socket.timeout:
                    print("failed")
                    if current_try == 3:
                        print("failed all connection attempts")
                        print("dropping connection attempt...")
                        contin = True
            if contin:
                continue
            print(f"connection to {ip}:{port} succeded!")
            connection_request_packet = build_peer_connecting(self.nickname)
            for current_try in range(0,3):
                try:
                    print("sending request")
                    new_socket.send(connection_request_packet)
                    break
                except socket.error as e:
                    print("failed to send request message:")
                    print(e)
                    if current_try >= 3:
                        print("failed to send")
                        print("dropping connection attempt...")
                        contin = True
                    else:
                        print("retrying")
            if contin:
                continue
            for current_try in range(0,3):
                data = bytes()
                try:
                    print("getting hostname")
                    data = new_socket.recv(1024)
                    break
                except socket.error as e:
                    print("failed to send request message:")
                    print(e)
                    if current_try >= 3:
                        print("failed to recive information")
                        print("dropping connection attempt...")
                        contin = True
                    else:
                        print("retrying")
                if contin:
                    continue
            msg_id, payload = parse_packet(data)
            target_nickname , valid = parse_peer_connecting(payload)
            if not valid:
                print("ICH HAB KEIN BOCK MEHR AUF DIESE BLÖDE KACK AUFGABE MANN ICH SITZ DA GRAD VIEL ZU LANG DRANN EY DAS KANN DOCH NICHT SEIN")
                continue
            print("succesfully established connection")
            self.tracked_user_tcp_socket[target_nickname] = new_socket

            return

    def handle_server_com(self):
        while True:
            # Check if input queue has data
            try:
                user_input = self.broadcast_queue.get_nowait()
            except queue.Empty:
                user_input = None

            if user_input:
                print(f"Handling user input for broadcast in server thread: {user_input}")
                packet = build_packet(0x04, user_input.encode())
                self.server_socket.send(packet)

            get_peers_packet = build_packet(0x02, b"")
            try:
                self.server_socket.send(get_peers_packet)
                time.sleep(1)
            except socket.timeout:
                continue
            try:
                data = self.server_socket.recv(1024)
            except socket.TimeoutError as e:
                print("TimeOut while trying to recieve list")
                continue
            msg_id, payload = parse_packet(data)
            if msg_id == 0x12:
                #print("got peers list")
                self.handle_send_peers(payload)
                self.LATEST_LIST_PRINTED = False
            elif msg_id == 0x04:
                print(f"[BROADCAST]: {payload.decode('utf-8')}")
            time.sleep(1)

    def parse_send_peers(self, payload: bytes) -> list[tuple[str, str, int]]:
        peers = []
        offset = 0

        if len(payload) < 1:
            raise ValueError("Payload zu kurz, keine Anzahl der Peers enthalten.")

        num_peers = payload[offset]
        offset += 1

        for _ in range(num_peers):
            if offset >= len(payload):
                raise ValueError("Unerwartetes Ende des Payloads beim Parsen von Peers.")

            nick_len = payload[offset]
            offset += 1

            nickname_bytes = payload[offset:offset + nick_len]
            nickname = nickname_bytes.decode("utf-8")
            offset += nick_len

            ip_bytes = payload[offset:offset + 4]
            ip = socket.inet_ntoa(ip_bytes)
            offset += 4

            port_bytes = payload[offset:offset + 2]
            port = struct.unpack(">H", port_bytes)[0]
            offset += 2
            peers.append((nickname, ip, port))
        return peers

    def handle_send_peers(self, payload: bytes):
        peer_list = self.parse_send_peers(payload)
        for nickname, ip, port in peer_list:
            if nickname == self.nickname or nickname in self.tracked_users_udp_socket.keys():
                continue

            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.tracked_users_udp_socket[nickname] = (ip, port)
                print(f"[INFO] Neuer Peer hinzugefügt: {nickname} @ {ip}:{port}")
            except Exception as e:
                print(f"[ERROR] Fehler beim Hinzufügen von Peer {nickname}: {e}")

    def printlist(self):
        while True:
            if not self.LATEST_LIST_PRINTED:
                #pprint.pprint(self.tracked_users_udp_socket)
                self.LATEST_LIST_PRINTED = True
            else:
                time.sleep(1)



def build_packet(msg_id: int, payload: bytes) -> bytes:
    payload_length = len(payload)
    return struct.pack(f">BH{payload_length}s", msg_id, payload_length, payload)

def parse_packet(packet: bytes) -> tuple[int, bytes]:
    header_format = ">BH"
    header_size = struct.calcsize(header_format)

    if len(packet) < header_size:
        raise ValueError("Paket zu kurz für Header.")

    msg_id, payload_length = struct.unpack(header_format, packet[:header_size])

    if len(packet) < header_size + payload_length:
        raise ValueError("Paket zu kurz für Payload.")

    payload_format = f">{payload_length}s"
    payload = struct.unpack(payload_format, packet[header_size:header_size + payload_length])[0]

    return msg_id, payload

def checksum(name: str) -> int:
    return sum(name.encode("utf-8")) % 256

def build_connection_request(ip: str, port: int) -> bytes:
    ip_bytes = socket.inet_aton(ip)  # 4 Bytes
    payload = ip_bytes + struct.pack(">H", port)
    return build_packet(0x05, payload)

def parse_connection_request(payload: bytes) -> tuple[str, int]:
    """returns ip, port"""
    if len(payload) != 6:
        raise ValueError(f"CONNECTION_REQUEST Payload muss 6 Bytes lang sein. Statdessen war: {len(payload)}")
    ip = socket.inet_ntoa(payload[:4])
    port = struct.unpack(">H", payload[4:6])[0]
    return ip, port

def build_peer_connecting(nickname: str)-> bytes:
    nickname_bytes = nickname.encode("utf-8")
    check_byte = checksum(nickname)
    payload = nickname_bytes + struct.pack("B", check_byte)
    return build_packet(0x15, payload)

def parse_peer_connecting(payload: bytes) -> tuple[str, bool]:
    if len(payload) < 2:
        raise ValueError("PEER_CONNECTING Payload zu kurz.")
    nickname_bytes = payload[:-1]
    check_byte = payload[-1]
    nickname = nickname_bytes.decode("utf-8")
    valid = checksum(nickname) == check_byte
    return nickname, valid

def build_message_to_peer(message: str) -> bytes:
    return build_packet(0x25, message.encode("utf-8"))

def parse_message_to_peer(payload: bytes) -> str:
    return payload.decode("utf-8")



# server broadcast
if __name__ == "__main__":
    current_client:clientImpl = clientImpl(input("Insert your Nickname: "))
    current_client.connect_to_server()

    print_thread = threading.Thread(target=current_client.printlist)
    print_thread.daemon = True
    print_thread.start()
    udp_thread = threading.Thread(target=current_client.listen_for_UDP_request)
    udp_thread.daemon = True
    udp_thread.start()

    recieve_thread = threading.Thread(target=current_client.recieve)
    recieve_thread.daemon = True
    recieve_thread.start()

    server_thread = threading.Thread(target=current_client.handle_server_com)
    server_thread.daemon = True
    server_thread.start()
    print("Type messages in the format: <nickname> <message>")
    print("Type 'exit' to quit.")

    current_input = ""
    while True:
        current_input = input()
        if current_input.lower() == "exit":
            break

        split = current_input.split(" ", 1)
        if len(split) == 2:
            target_nickname = split[0]
            target_msg = split[1]
            if target_nickname == "broadcast":
                current_client.broadcast_queue.put(target_msg)
            else:
                current_client.send(target_nickname, target_msg)
        else:
            print("invallid format")
    print("closing connection")
    current_client.server_socket.close()
    current_client.udp_socket.close()
    for sock in current_client.tracked_user_tcp_socket.values():
        sock.close()
        print("goodbye")
