#!/usr/bin/env python3
"""Generic inline plugin shim: bridges lightningd stdio <-> inline-plugin.sock in cwd.
Used by inline_plugin() in pyln/testing/utils.py."""
import os
import socket
import sys
import threading


def _stdin_to_sock(conn):
    while chunk := sys.stdin.buffer.read1(4096):
        conn.sendall(chunk)
    # Stdin closed means lightningd is done with us: exit immediately so the
    # OS closes the socket and the serve thread can accept the next connection.
    os._exit(0)


conn = socket.socket(socket.AF_UNIX)
conn.connect('inline-plugin.sock')

threading.Thread(target=_stdin_to_sock, args=(conn,), daemon=True).start()

while chunk := conn.recv(4096):
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
