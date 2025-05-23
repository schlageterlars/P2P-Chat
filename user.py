from dataclasses import dataclass

class User:
    address: tuple[str, int]
    nickname: str
    
    @classmethod
    def from_tuple(cls, data: tuple[str, int, str]) -> "User":
        ip, port, nickname = data
        return cls(address=(ip, port), nickname=nickname)

    def to_tuple(self) -> tuple[str, int, str]:
        ip, port = self.address
        return (ip, port, self.nickname)