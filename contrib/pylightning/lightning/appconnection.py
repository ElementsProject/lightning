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
        self.read_buffer = b''


    def handle_read(self):
        data = self.recv(1024)
        self.logger.debug('Received: ' + repr(data))
        self.read_buffer += data

        try:
            obj, end_index = self.decoder.raw_decode(
                self.read_buffer.decode('UTF-8')
                )
        except ValueError:
            # Probably didn't read enough
            return
        self.read_buffer = self.read_buffer[end_index:]

        #FIXME: check method name (must be handle_payment)
        #FIXME: handle exceptions in handle_payment
        result = self.handle_payment(**obj['params'])

        s = json.dumps({'id': obj['id'], 'result': result})
        self.send(bytearray(s, 'UTF-8'))


    BADONION = 0x8000
    PERM     = 0x4000
    NODE     = 0x2000
    UPDATE   = 0x1000

    #return values for handle_payment:
    OK                     = 0
    INVALID_REALM          = PERM|1
    TEMPORARY_NODE_FAILURE = NODE|2
    PERMANENT_NODE_FAILURE = PERM|NODE|2
    #FIXME: add the rest (see BOLT #4)

    def handle_payment(self, realm):
        #to be replaced in derived classes
        #By default, fail a transaction immediately
        return AppConnection.PERMANENT_NODE_FAILURE

