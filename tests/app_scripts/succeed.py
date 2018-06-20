#! /usr/bin/env python3

import struct
import sys

APP_FORWARDED = 0
APP_NOT_FORWARDED = 1
APP_UNKNOWN = 2

sys.stdout.buffer.write(struct.pack('B', APP_FORWARDED))

