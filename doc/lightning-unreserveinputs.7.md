lightning-unreserveinputs -- Release reserved UTXOs
===================================================

SYNOPSIS
--------

**unreserveinputs** *psbt* [*reserve*] 

DESCRIPTION
-----------

The **unreserveinputs** RPC command releases (or reduces reservation) on UTXOs which were previously marked as reserved, generally by lightning-reserveinputs(7).

- **psbt** (string): Inputs to unreserve are the inputs specified in the passed-in *psbt*.
- **reserve** (u32, optional): The number of blocks to decrease reservation by. The default is 72.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:unreserveinputs#1",
  "method": "unreserveinputs",
  "params": {
    "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQECAQYBAwH7BAIAAAAAAQDeAgAAAAABAXyy20ynmOFyRbegGyApk50yNIAb4C+RKV5c2n5VKL3lAAAAAAD9////Akf0EAAAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WUs/fQpAQAAABYAFN9HebR4q6498ytdeRKjC64CkCOMAkcwRAIgSTJCpWVH1FLZYPdwFe7gZckxCtk+AxPp20KUVKqPIdUCIA3hkoUco68vffiwt6TrE3KgX09JE9m7PDUUgrHQANMRASEDBOBlCza/8qXE5q8uJ+OWsKscDERWfdA+LLCa/lwMH0BlAAAAAQEfR/QQAAAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZSICA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPRzBEAiBKjSasyN29ODqXSemEQCZfRIvbJP8thKRBrd4e+NLEMQIgMGNz3+DWDnLmjnIDCaVcC7BKxuycwvtJq1qlKFtTaXcBIgYD10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8IAfrZCgAAAAABDiAoXS6QUlCcOApG/j+hr4OhNt0tT4GvCzI6z16Hepi7OwEPBAAAAAABEAT9////AAEDCCN6CAAAAAAAAQQWABQfJ4Qjje0sa2yGBz++6jkM2hGRmAz8CWxpZ2h0bmluZwQCAAEAAQMIinkIAAAAAAABBCJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aIQeRRTKBKkQKTXZscc05GTaUo0CuEeAS5boa2e+6bnbKUwkAwsyrFwIAAAAA",
    "reserve": 200
  }
}
{
  "id": "example:unreserveinputs#2",
  "method": "unreserveinputs",
  "params": {
    "psbt": "cHNidP8BAF4CAAAAAVa79WPJoiYrzo/RgzIAn5HanoBFZo0vZvEjxPAVwLv4AAAAAAD9////AXzpHAAAAAAAIlEgBRjpLNlOD2LAbxJt/5i5q+ebfthFoVbVJFZ44mVUR11mAAAAAAEA3gIAAAAAAQENwcSElLyC0jcwUHiODBhtapHyzIdiwytOGiu/Raf4BwAAAAAA/f///wKAhB4AAAAAABYAFAH62Qq81maX4lkhZHIt5KlevuFl82znKQEAAAAWABQyIWyAI6LDf6dJ58BDPdkh+PWUZwJHMEQCIGiJFhVi/d/Hz19Cz48uHTjhgBJ6WAlgl/bLVS7A6VtxAiAwlb7xYzIM4uopFvMnpOmGIOp3+upOPPF2F8VaB8U/HQEhA6BAjey7RADP4ifoh2VXhX7QXkh+sZqozv1EPuU5TxZmZQAAAAEBH4CEHgAAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WUAAA==",
    "reserve": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **reservations** is returned. It is an array of objects, where each object contains:

- **txid** (txid): The transaction id.
- **vout** (u32): The output number which was reserved.
- **was\_reserved** (boolean): Whether the input was already reserved (usually `true`).
- **reserved** (boolean): Whether the input is now reserved (may still be `true` if it was reserved for a long time).

If **reserved** is *true*:
  - **reserved\_to\_block** (u32): What blockheight the reservation will expire.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "reservations": [
    {
      "txid": "3bbb987a875ecf3a320baf814f2ddd36a183afa13ffe460a389c5052902e5d28",
      "vout": 0,
      "was_reserved": true,
      "reserved": false
    }
  ]
}
{
  "reservations": []
}
```

ERRORS
------

On failure, an error is reported and no UTXOs are unreserved.

- -32602: Invalid parameter, i.e. an unparseable PSBT.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-unreserveinputs(7), lightning-signpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
