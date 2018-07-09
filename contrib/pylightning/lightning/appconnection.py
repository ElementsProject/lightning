import json
import logging
import socket
import asyncore


class AppConnection(asyncore.dispatcher_with_send):
    def __init__(self, socket_path, logger=logging, map=None):
        self.decoder = json.JSONDecoder()
        self.logger = logger

        asyncore.dispatcher_with_send.__init__(self, map=map)
        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connect(socket_path)

    def handle_read(self):
        data = self.recv(1024)
        self.logger.debug('Received: ' + repr(data))

    def handle_payment(self):
        pass #to be replaced in derived classes

