lightning-reserveinputs -- Construct a transaction and reserve the UTXOs it spends
==================================================================================

SYNOPSIS
--------

**reserveinputs** *psbt* [*exclusive*] [*reserve*] 

DESCRIPTION
-----------

The **reserveinputs** RPC command places (or increases) reservations on any inputs specified in *psbt* which are known to lightningd. It will fail with an error if any of the inputs are known to be spent, and ignore inputs which are unknown.

Normally the command will fail (with no reservations made) if an input is already reserved.

- **psbt** (string): The PSBT to reserve inputs from.
- **exclusive** (boolean, optional): If set to *False*, existing reservations are simply extended, rather than causing failure.
- **reserve** (u32, optional): The number of blocks to reserve. By default, reservations are for the next 72 blocks (approximately 6 hours).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:reserveinputs#1",
  "method": "reserveinputs",
  "params": {
    "psbt": "cHNidP8BAFwCAAAAAkwJVUqB0xXTO7JZ3PnPdGnxoYfQxhU+xqXGFYXsyX0RAAAAAAD9////TAlVSoHTFdM7slnc+c90afGhh9DGFT7GpcYVhezJfREBAAAAAP3///8AAAAAAAAAAA==",
    "exclusive": true,
    "reserve": null
  }
}
{
  "id": "example:reserveinputs#2",
  "method": "reserveinputs",
  "params": {
    "psbt": "cHNidP8BAP32AQIAAAAMgnW099dbh1uD153ih5eU5WhluynLxekXjAOjkEdNBg8BAAAAAP3///9FWKQt8C+1y4741+beFSqWAaj9DuvzHNpxvpxS+GB8lwEAAAAA/f///6E5TAGqktI29Oso6b9kZZoAFFGGvpJQUM8VO+3LMTlmAAAAAAD9////nSDT7hrkuoQtAV1yNnbpkJsB5ifKoM2zP+CcLPfis1gBAAAAAP3///+P1rW90UXfD0gIk58h3sXxxy3ZfJJLP0H1I4Jpzy/87QEAAAAA/f///w0UKZ/s9DnPpV+FJ8h2BEI7tl+qVxSGRFRv9FYw4girAQAAAAD9////EPNsUFrEOZyfjbqbh8rfHQ4C9RQECw12n3c1yhFqkzoAAAAAAP3///8QW9LEsSmuvSnvVzy+FDktM7ewQmZnIJI/TJMahLmSzwEAAAAA/f///+4edbWRHDdRJcMeHHElgSmb+nENPsz/g/0AmAEU6hXeAAAAAAD9////T15YLGmk7HBsrL+awdcxi3db3esp8AcCTS9XGrEnfoAAAAAAAP3///8q7xInvEk7J0Ir9cpKXqU2lArUskkYLrimIE0+Yb6a2QEAAAAA/f///8hBLKyMa2zRJqwNOk7DmsDIfG7IvJtQiJ+QnkkHl6atAAAAAAD9////AAAAAAAAAAAAAAAAAAAAAAAA",
    "exclusive": false,
    "reserve": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **reservations** is returned. It is an array of objects, where each object contains:

- **txid** (txid): The input transaction id.
- **vout** (u32): The input index output number which was reserved.
- **was\_reserved** (boolean): Whether the input was already reserved.
- **reserved** (boolean) (always *true*): Whether the input is now reserved.
- **reserved\_to\_block** (u32): What blockheight the reservation will expire.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "reservations": [
    {
      "txid": "117dc9ec8515c6a5c63e15c6d087a1f16974cff9dc59b23bd315d3814a55094c",
      "vout": 1,
      "was_reserved": false,
      "reserved": true,
      "reserved_to_block": 175
    }
  ]
}
{
  "reservations": [
    {
      "txid": "0f064d4790a3038c17e9c5cb29bb6568e5949787e29dd7835b875bd7f7b47582",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "977c60f8529cbe71da1cf3eb0efda801962a15dee6d7f88ecbb52ff02da45845",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "663931cbed3b15cf505092be865114009a6564bfe928ebf436d292aa014c39a1",
      "vout": 0,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "58b3e2f72c9ce03fb3cda0ca27e6019b90e97636725d012d84bae41aeed3209d",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "edfc2fcf698223f5413f4b927cd92dc7f1c5de219f9308480fdf45d1bdb5d68f",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "ab08e23056f46f5444861457aa5fb63b420476c827855fa5cf39f4ec9f29140d",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "3a936a11ca35779f760d0b0414f5020e1ddfca879bba8d9f9c39c45a506cf310",
      "vout": 0,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "cf92b9841a934c3f9220676642b0b7332d3914be3c57ef29bdae29b1c4d25b10",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "de15ea14019800fd83ffcc3e0d71fa9b298125711c1ec32551371c91b5751eee",
      "vout": 0,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "807e27b11a572f4d0207f029ebdd5b778b31d7c19abfac6c70eca4692c585e4f",
      "vout": 0,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "d99abe613e4d20a6b82e1849b2d40a9436a55e4acaf52b42273b49bc2712ef2a",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "ada69707499e909f88509bbcc86e7cc8c09ac34e3a0dac26d16c6b8cac2c41c8",
      "vout": 0,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    }
  ]
}
```

ERRORS
------

On failure, an error is reported and no UTXOs are reserved.

- -32602: Invalid parameter, such as specifying a spent/reserved input in *psbt*.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-unreserveinputs(7), lightning-signpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
