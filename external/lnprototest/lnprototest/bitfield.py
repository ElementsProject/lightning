#! /usr/bin/python3
from typing import Union, List


def bitfield_len(bitfield: Union[List[int], str]) -> int:
    """Return length of this field in bits (assuming it's a bitfield!)"""
    if isinstance(bitfield, str):
        return len(bytes.fromhex(bitfield)) * 8
    else:
        return len(bitfield) * 8


def has_bit(bitfield: Union[List[int], str], bitnum: int) -> bool:
    """Test bit in this bitfield (little-endian, as per BOLTs)"""
    bitlen = bitfield_len(bitfield)
    if bitnum >= bitlen:
        return False

    # internal to a msg, it's a list of int.
    if isinstance(bitfield, str):
        byte = bytes.fromhex(bitfield)[bitlen // 8 - 1 - bitnum // 8]
    else:
        byte = bitfield[bitlen // 8 - 1 - bitnum // 8]

    if (byte & (1 << (bitnum % 8))) != 0:
        return True
    else:
        return False


def bitfield(*args: int) -> str:
    """Create a bitfield hex value with these bit numbers set"""
    bytelen = (max(args) + 8) // 8
    bfield = bytearray(bytelen)
    for bitnum in args:
        bfield[bytelen - 1 - bitnum // 8] |= 1 << (bitnum % 8)
    return bfield.hex()
