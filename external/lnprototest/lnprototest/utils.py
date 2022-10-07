#! /usr/bin/python3
import string
import coincurve
import time
import typing
from enum import IntEnum

# regtest chain hash (hash of regtest genesis block)
regtest_hash = "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"


class Side(IntEnum):
    local = 0
    remote = 1

    def __not__(self) -> "Side":
        if self == Side.local:
            return Side.remote
        return Side.local


def check_hex(val: str, digits: int) -> str:
    if not all(c in string.hexdigits for c in val):
        raise ValueError("{} is not valid hex".format(val))
    if len(val) != digits:
        raise ValueError("{} not {} characters long".format(val, digits))
    return val


def privkey_expand(secret: str) -> coincurve.PrivateKey:
    # Privkey can be truncated, since we use tiny values a lot.
    return coincurve.PrivateKey(bytes.fromhex(secret).rjust(32, bytes(1)))


def wait_for(success: typing.Callable, timeout: int = 180) -> None:
    start_time = time.time()
    interval = 0.25
    while not success():
        time_left = start_time + timeout - time.time()
        if time_left <= 0:
            raise ValueError("Timeout while waiting for {}", success)
        time.sleep(min(interval, time_left))
        interval *= 2
        if interval > 5:
            interval = 5
