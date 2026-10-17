from dataclasses import dataclass
from typing import Optional


@dataclass
class Packet:
    timestamp: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_mac: Optional[str]
    dst_mac: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    length: int
    ttl: Optional[int]
    tcp_flags: Optional[str]
    raw_data: Optional[bytes]


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: int
    end_time: int
    packet_count: int
    bytes_transferred: int


@dataclass
class Host:
    ip: str
    mac: Optional[str]
    hostname: Optional[str]
    first_seen: int
    last_seen: int
    packet_count: int
