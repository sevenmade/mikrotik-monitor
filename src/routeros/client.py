from __future__ import annotations

import socket
import ssl
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Optional

from src.routeros.api import ApiRos


class RouterOsError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoginInfo:
    host: str
    port: int
    username: str
    password: str
    use_tls: bool = False


class RouterOsClient(AbstractContextManager):
    def __init__(self, login_info: LoginInfo, connect_timeout: float, command_timeout: float):
        self.login_info = login_info
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self._socket: Optional[socket.socket] = None
        self._api: Optional[ApiRos] = None

    def __enter__(self) -> "RouterOsClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        try:
            address_info = socket.getaddrinfo(
                self.login_info.host,
                self.login_info.port,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
            family, sock_type, proto, _, sockaddr = address_info[0]
            raw_socket = socket.socket(family, sock_type, proto)
            raw_socket.settimeout(self.connect_timeout)
            if self.login_info.use_tls:
                raw_socket = ssl.wrap_socket(raw_socket, ssl_version=ssl.PROTOCOL_TLSv1_2)
            raw_socket.connect(sockaddr)
            raw_socket.settimeout(self.command_timeout)
            self._socket = raw_socket
            self._api = ApiRos(raw_socket)
            if not self._api.login(self.login_info.username, self.login_info.password):
                raise RouterOsError(f"login failed for {self.login_info.host}:{self.login_info.port}")
        except Exception as exc:
            self.close()
            raise RouterOsError(f"connect failed for {self.login_info.host}:{self.login_info.port}: {exc}") from exc

    def talk(self, command: list[str]):
        if self._api is None:
            raise RouterOsError("client is not connected")
        try:
            return self._api.talk(command)
        except Exception as exc:
            raise RouterOsError(f"command failed: {command[0] if command else 'unknown'}: {exc}") from exc

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None
                self._api = None
