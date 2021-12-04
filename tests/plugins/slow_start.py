#!/usr/bin/env python3
"""This plugin is used to check that updated connection hints work properly.

"""
from pyln.client import Plugin

import socket
import time

plugin = Plugin()


@plugin.async_method('waitconn')
def wait_connection(request, plugin):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    sock.listen(1)
    print("listening for connections on port {}".format(sock.getsockname()[1]))

    # We are a one and done socket connection!
    conn, client_addr = sock.accept()
    try:
        print("connection from {}".format(client_addr))
        time.sleep(3)

    finally:
        conn.close()

    print("closing socket")
    sock.close()


plugin.run()
