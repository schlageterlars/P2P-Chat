import socket
import threading
from user import User
from server import Server

MSG_REGISTER = 0x01
MSG_REGISTER_RESPONSE = 0x11
MSG_GET_PEERS = 0x02
MSG_SEND_PEERS = 0x12
MSG_PEERS_CHANGED = 0x03
MSG_SEND_BROADCAST = 0x04
MSG_FROM_SERVER = 0x14

STATUS_SUCCESS = 0x01
STATUS_FAIL = 0x02
STATUS_PEER_REMOVED = 0x01
STATUS_PEER_ADDED = 0x02

class ChatServer(Server):
    def __init__(self, host='10.147.85.98', port=12345):
        self.clients = {}
        self.lock = threading.Lock()
        self.host = host
        self.port = port

    def start(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen()
        print(f"[INFO] Server läuft auf {self.host}:{self.port}")

        while True:
            try:
                client_sock, addr = server_sock.accept()
                print(f"[INFO] Neue Verbindung von {addr}")
                threading.Thread(target=self.receive, args=(client_sock,), daemon=True).start()
            except Exception as e:
                print(f"[ERROR] Fehler beim accept: {e}")

    def receive(self, sock):
        while True:
            try:
                header = sock.recv(3)
                if len(header) < 3:
                    break
                msg_id, payload_len = header[0], int.from_bytes(header[1:3], 'big')
                payload = sock.recv(payload_len)

                if msg_id == MSG_REGISTER:
                    self.handle_register(sock, payload)
                elif msg_id == MSG_GET_PEERS:
                    self.send_peer_list(sock)
                elif msg_id == MSG_SEND_BROADCAST:
                    self.broadcast(payload.decode(), sock)
                elif msg_id == MSG_PEERS_CHANGED:
                    nickname_len = payload[0]
                    nickname = payload[1:1+nickname_len].decode()
                    status = payload[1+nickname_len]
                    user = self.clients.get(nickname)
                    if user:
                        if status == STATUS_PEER_REMOVED:
                            self.deregister(nickname)
                        elif status == STATUS_PEER_ADDED:
                            self.send_peer_change(user, STATUS_PEER_ADDED)
                else:
                    print(f"[WARN] Unbekannte Nachricht: {msg_id}")
            except Exception as e:
                print(f"[ERROR] receive(): {e}")
                break

    def handle_register(self, sock, payload):
        nickname_len = payload[0]
        nickname = payload[1:1+nickname_len].decode()
        ip_bytes = payload[1+nickname_len:1+nickname_len+4]
        port_bytes = payload[1+nickname_len+4:1+nickname_len+6]
        ip = ".".join(str(b) for b in ip_bytes)
        port = int.from_bytes(port_bytes, 'big')

        with self.lock:
            if nickname in self.clients:
                self.send_register_response(sock, STATUS_FAIL)
                return
            user = User.from_tuple((ip, port, nickname))
            self.clients[nickname] = user
            self.send_register_response(sock, STATUS_SUCCESS)
            print(f"[INFO] {nickname} registriert von {ip}:{port}")
            self.send_peer_change(user, STATUS_PEER_ADDED)

    def send_register_response(self, sock, status_code):
        msg = bytes([MSG_REGISTER_RESPONSE, 0x00, 0x01, status_code])
        sock.sendall(msg)

    def send_peer_list(self, sock):
        with self.lock:
            entries = b''.join(self.encode_peer(u) for u in self.clients.values())
            msg = bytes([MSG_SEND_PEERS, 0x00, len(entries)+1, len(self.clients)]) + entries
            sock.sendall(msg)

    def encode_peer(self, user: User) -> bytes:
        nickname_bytes = user.nickname.encode()
        ip_bytes = bytes(map(int, user.address[0].split('.')))
        port_bytes = user.address[1].to_bytes(2, 'big')
        return bytes([len(nickname_bytes)]) + nickname_bytes + ip_bytes + port_bytes

    def deregister(self, nickname: str):
        with self.lock:
            user = self.clients.pop(nickname, None)
            if user:
                self.send_peer_change(user, STATUS_PEER_REMOVED)
                print(f"[INFO] {nickname} abgemeldet")

    def list(self) -> list[User]:
        with self.lock:
            return list(self.clients.values())


    def send_peer_change(self, user: User, status: int):
        data = self.encode_peer(user) + bytes([status])
        header = bytes([MSG_PEERS_CHANGED]) + len(data).to_bytes(2, 'big')
        msg = header + data

        for peer in self.clients.values():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(peer.address)
                sock.sendall(msg)
                sock.close()
            except:
                continue

    def broadcast(self, message: str, origin_sock):
        with self.lock:
            payload = message.encode()
            msg = bytes([MSG_FROM_SERVER]) + len(payload).to_bytes(2, 'big') + payload
            for user in self.clients.values():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect(user.address)
                    sock.sendall(msg)
                    sock.close()
                except Exception as e:
                    print(f"[WARN] Broadcast an {user.nickname} fehlgeschlagen: {e}")

if __name__ == "__main__":
    server = ChatServer()
    server.start()
