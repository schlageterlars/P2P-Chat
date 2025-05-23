from abc import abstractmethod
from user import User

class Client:
    @abstractmethod
    def connect_to_server(): 
        pass
    
    @abstractmethod
    def send(nickname: str, msg: str):
        ## send tcp connection informations per udp to other client
        ## send message to user with $nickname
        pass
    
    @abstractmethod
    def receive():
        pass