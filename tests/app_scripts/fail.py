#! /usr/bin/env python3

import struct
import sys

APP_FORWARDED = 0
APP_NOT_FORWARDED = 1
APP_UNKNOWN = 2

#copy stdin to a file
with open('app-script-input', 'wb') as f:
    while True:
        data = sys.stdin.buffer.read()
        if not data:
            break
        f.write(data)

sys.stdout.buffer.write(struct.pack('B', APP_NOT_FORWARDED))

