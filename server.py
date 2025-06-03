from abc import abstractmethod
from user import User


class Server:
    @abstractmethod
    def register(address: tuple[str, int], nickname: str): 
        pass
    
    @abstractmethod
    def deregister(self, nickname: str):
        pass
    
    @abstractmethod
    def list(self) -> list[User]:
        pass
    
    @abstractmethod
    def send_to_all(from_nickname: str, msg: str):
        pass
    
    @abstractmethod
    def receive(self, sock):
        pass
