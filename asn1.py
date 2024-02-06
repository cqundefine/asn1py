from dataclasses import dataclass
import datetime

@dataclass
class Node:
    length: int
    constructed: bool

@dataclass
class Invalid(Node):
    pass

@dataclass
class Boolean(Node):
    value: bool

@dataclass
class Integer(Node):
    value: int

@dataclass
class Null(Node):
    pass

@dataclass
class ObjectIdentifier(Node):
    value: list[int]

    def __str__(self):
        return '.'.join(map(str, self.value))

@dataclass
class Sequence(Node):
    children: list[Node]

@dataclass
class Set(Node):
    children: list[Node]

@dataclass
class PrintableString(Node):
    value: str

@dataclass
class UTCTime(Node):
    value: datetime.datetime

@dataclass
class ContextSpecific(Node):
    tag: int
    value: Node    
