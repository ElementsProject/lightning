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


    #return values for handle_payment:
    PAYMENT_KEEP   = 1 #Keep the payment for now       (we may have a way to get the preimage)
    PAYMENT_REJECT = 0 #Reject the payment immediately (we don't have a way to get the preimage)

    def handle_payment(self, realm):
        #to be replaced in derived classes
        #By default, cancel a transaction immediately
        return AppConnection.PAYMENT_REJECT

