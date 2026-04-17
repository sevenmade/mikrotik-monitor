from __future__ import annotations

import binascii
import hashlib


class ApiRos:
    def __init__(self, socket_obj):
        self.socket = socket_obj

    def login(self, username: str, password: str) -> bool:
        for reply, attrs in self.talk(["/login", f"=name={username}", f"=password={password}"]):
            if reply == "!trap":
                return False
            if "=ret" in attrs:
                challenge = binascii.unhexlify(attrs["=ret"].encode("utf-8"))
                md5_hash = hashlib.md5()
                md5_hash.update(b"\x00")
                md5_hash.update(password.encode("utf-8"))
                md5_hash.update(challenge)
                response = "00" + binascii.hexlify(md5_hash.digest()).decode("utf-8")
                for reply2, _ in self.talk(["/login", f"=name={username}", f"=response={response}"]):
                    if reply2 == "!trap":
                        return False
        return True

    def talk(self, words: list[str]):
        if self._write_sentence(words) == 0:
            return []

        response = []
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            reply = sentence[0]
            attrs: dict[str, str] = {}
            for word in sentence[1:]:
                split = word.find("=", 1)
                if split == -1:
                    attrs[word] = ""
                else:
                    attrs[word[:split]] = word[split + 1 :]
            response.append((reply, attrs))
            if reply == "!done":
                return response

    def _write_sentence(self, words: list[str]) -> int:
        written = 0
        for word in words:
            self._write_word(word)
            written += 1
        self._write_word("")
        return written

    def _read_sentence(self) -> list[str]:
        sentence: list[str] = []
        while True:
            word = self._read_word()
            if word == "":
                return sentence
            sentence.append(word)

    def _write_word(self, word: str) -> None:
        self._write_len(len(word))
        self._write_str(word)

    def _read_word(self) -> str:
        return self._read_str(self._read_len())

    def _write_len(self, length: int) -> None:
        if length < 0x80:
            self._write_byte(length.to_bytes(1, "big"))
        elif length < 0x4000:
            length |= 0x8000
            self._write_byte(((length >> 8) & 0xFF).to_bytes(1, "big"))
            self._write_byte((length & 0xFF).to_bytes(1, "big"))
        elif length < 0x200000:
            length |= 0xC00000
            self._write_byte(((length >> 16) & 0xFF).to_bytes(1, "big"))
            self._write_byte(((length >> 8) & 0xFF).to_bytes(1, "big"))
            self._write_byte((length & 0xFF).to_bytes(1, "big"))
        elif length < 0x10000000:
            length |= 0xE0000000
            self._write_byte(((length >> 24) & 0xFF).to_bytes(1, "big"))
            self._write_byte(((length >> 16) & 0xFF).to_bytes(1, "big"))
            self._write_byte(((length >> 8) & 0xFF).to_bytes(1, "big"))
            self._write_byte((length & 0xFF).to_bytes(1, "big"))
        else:
            self._write_byte((0xF0).to_bytes(1, "big"))
            self._write_byte(((length >> 24) & 0xFF).to_bytes(1, "big"))
            self._write_byte(((length >> 16) & 0xFF).to_bytes(1, "big"))
            self._write_byte(((length >> 8) & 0xFF).to_bytes(1, "big"))
            self._write_byte((length & 0xFF).to_bytes(1, "big"))

    def _read_len(self) -> int:
        value = ord(self._read_str(1))
        if (value & 0x80) == 0x00:
            return value
        if (value & 0xC0) == 0x80:
            value &= ~0xC0
            return (value << 8) + ord(self._read_str(1))
        if (value & 0xE0) == 0xC0:
            value &= ~0xE0
            value = (value << 8) + ord(self._read_str(1))
            return (value << 8) + ord(self._read_str(1))
        if (value & 0xF0) == 0xE0:
            value &= ~0xF0
            value = (value << 8) + ord(self._read_str(1))
            value = (value << 8) + ord(self._read_str(1))
            return (value << 8) + ord(self._read_str(1))
        if (value & 0xF8) == 0xF0:
            value = ord(self._read_str(1))
            value = (value << 8) + ord(self._read_str(1))
            value = (value << 8) + ord(self._read_str(1))
            return (value << 8) + ord(self._read_str(1))
        return value

    def _write_str(self, value: str) -> None:
        payload = value.encode("utf-8")
        sent = 0
        while sent < len(payload):
            write_size = self.socket.send(payload[sent:])
            if write_size == 0:
                raise RuntimeError("connection closed by remote end")
            sent += write_size

    def _write_byte(self, value: bytes) -> None:
        sent = 0
        while sent < len(value):
            write_size = self.socket.send(value[sent:])
            if write_size == 0:
                raise RuntimeError("connection closed by remote end")
            sent += write_size

    def _read_str(self, length: int) -> str:
        read_buffer = b""
        while len(read_buffer) < length:
            chunk = self.socket.recv(length - len(read_buffer))
            if chunk == b"":
                raise RuntimeError("connection closed by remote end")
            read_buffer += chunk
        return read_buffer.decode("utf-8", "replace")
