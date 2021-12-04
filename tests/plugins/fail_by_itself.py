#!/usr/bin/env python3
from pyln.client import Plugin
import os
import threading
import time

plugin = Plugin()


class FailThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.start()

    def run(self):
        time.sleep(1)
        print("Exiting!")
        os._exit(1)


@plugin.init()
def init(options, configuration, plugin):
    FailThread()


@plugin.method('failcmd')
def failcmd(plugin):
    pass


plugin.run()
