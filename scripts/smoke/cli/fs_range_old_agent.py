#!/usr/bin/env python3
"""Require an actual v0.7.6-gitii.13 guest to refuse the ReadRange operation."""

import socket
import struct
import sys

from transport_tcp import cbor, uncbor


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("old agent closed before its refusal")
        data.extend(part)
    return bytes(data)


def message(sock):
    length = struct.unpack(">I", receive(sock, 4))[0]
    if not 5 <= length <= 4 * 1024 * 1024:
        raise RuntimeError(f"invalid frame length: {length}")
    body = receive(sock, length)
    identifier, flags = struct.unpack(">IB", body[:5])
    envelope = uncbor(body[5:])
    return identifier, flags, envelope


def main(path):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(path)
        minimum, maximum = struct.unpack(">II", receive(sock, 8))
        assert 0 < minimum < maximum, (minimum, maximum)
        _, _, ready = message(sock)
        assert ready["t"] == "core.ready", ready
        payload = {"op": {"ReadRange": {"handle": 1, "offset": 7, "len": 9}}}
        body = struct.pack(">IB", minimum, 2) + cbor({
            "v": ready["v"], "t": "core.fs.request", "p": cbor(payload),
        })
        sock.sendall(struct.pack(">I", len(body)) + body)
        identifier, flags, reply = message(sock)
        error = uncbor(reply["p"])
        assert identifier == minimum, (identifier, minimum)
        assert flags & 1, flags
        assert reply["t"] == "core.error", reply
        assert "unknown variant `ReadRange`" in error["message"], error
        print(error)


if __name__ == "__main__":
    main(sys.argv[1])
