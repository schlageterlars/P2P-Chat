from dataclasses import dataclass
import socket
class User:
    address: tuple[str, int]
    sock: socket.socket
    nickname: str

    def __init__(self, address: tuple[str, int], sock: socket.socket, nickname: str):
        self.address = address
        self.sock = sock
        self.nickname = nickname
    @classmethod
    def from_tuple(cls, data: tuple[str, int, socket.socket, str]) -> "User":
        ip, port, sock, nickname = data
        return cls(address=(ip, port), sock=sock, nickname=nickname)

    def to_tuple(self) -> tuple[str, int, socket.socket, str]:
        ip, port = self.address
        return (ip, port, self.sock, self.nickname)