import abc
import socket

from .server import Server

class serverImpl(Server):
    
    ip_addr: str = ""

def __init__(self, ip_addr: str):
    self.ip_addr = ip_addr