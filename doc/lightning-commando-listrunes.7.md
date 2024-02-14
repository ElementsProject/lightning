lightning-commando-listrunes -- Command to list previously generated runes
==========================================================================

SYNOPSIS
--------

**commando-listrunes** [*rune*] 

DESCRIPTION
-----------

Command **deprecated in v23.08, removed after v24.05**.

Command *added* in v23.05.

The **commando-listrunes** RPC command either lists runes that we stored as we generate them (see lightning-commando-rune(7)) or decodes the rune given on the command line.

NOTE: Runes generated prior to v23.05 were not stored, so will not appear in this list.

- **rune** (string, optional): Optional rune to list.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:commando-listrunes#1",
  "method": "commando-listrunes",
  "params": "{}"
}
{
  "id": "example:commando-listrunes#2",
  "method": "commando-listrunes",
  "params": {
    "rune": "Am3W_wI0PRn4qVNEsJ2iInHyFPQK8wfdqEXztm8-icQ9MA=="
  }
}
{
  "id": "example:commando-listrunes#3",
  "method": "commando-listrunes",
  "params": {
    "rune": "m_tyR0qqHUuLEbFJW6AhmBg-9npxVX2yKocQBFi9cvY9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8mcGFycjEhfHBhcnIxL2lv"
  }
}
```

RETURN VALUE
------------

On success, an object containing **runes** is returned. It is an array of objects, where each object contains:

- **rune** (string): Base64 encoded rune.
- **unique\_id** (string): Unique id assigned when the rune was generated; this is always a u64 for commando runes.
- **restrictions** (array of objects): The restrictions on what commands this rune can authorize.:
  - **alternatives** (array of objects):
    - **fieldname** (string): The field this restriction applies to; see commando-rune(7).
    - **value** (string): The value accepted for this field.
    - **condition** (string): The way to compare fieldname and value.
    - **english** (string): English readable description of this alternative.
  - **english** (string): English readable summary of alternatives above.
- **restrictions\_as\_english** (string): English readable description of the restrictions array above.
- **stored** (boolean, optional) (always *false*): This is false if the rune does not appear in our datastore (only possible when `rune` is specified).
- **blacklisted** (boolean, optional) (always *true*): The rune has been blacklisted; see commando-blacklist(7).
- **last\_used** (number, optional): The last time this rune was successfully used. *(added 23.11)*
- **our\_rune** (boolean, optional) (always *false*): This is not a rune for this node (only possible when `rune` is specified).

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "runes": [
    {
      "rune": "OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==",
      "unique_id": "0",
      "restrictions": [],
      "restrictions_as_english": ""
    },
    {
      "rune": "Am3W_wI0PRn4qVNEsJ2iInHyFPQK8wfdqEXztm8-icQ9MA==",
      "stored": false,
      "our_rune": false,
      "unique_id": "1",
      "restrictions": [],
      "restrictions_as_english": ""
    }
  ]
}
{
  "runes": [
    {
      "rune": "Am3W_wI0PRn4qVNEsJ2iInHyFPQK8wfdqEXztm8-icQ9MA==",
      "stored": false,
      "our_rune": false,
      "unique_id": "1",
      "restrictions": [],
      "restrictions_as_english": ""
    }
  ]
}
{
  "runes": [
    {
      "rune": "m_tyR0qqHUuLEbFJW6AhmBg-9npxVX2yKocQBFi9cvY9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8mcGFycjEhfHBhcnIxL2lv",
      "stored": false,
      "unique_id": "3",
      "restrictions": [
        {
          "alternatives": [
            {
              "fieldname": "id",
              "value": "022d223620a359a47ff7",
              "condition": "^",
              "english": "id starts with 022d223620a359a47ff7"
            }
          ],
          "english": "id starts with 022d223620a359a47ff7"
        },
        {
          "alternatives": [
            {
              "fieldname": "method",
              "value": "listpeers",
              "condition": "=",
              "english": "method equal to listpeers"
            }
          ],
          "english": "method equal to listpeers"
        },
        {
          "alternatives": [
            {
              "fieldname": "pnamelevel",
              "value": "",
              "condition": "!",
              "english": "pnamelevel is missing"
            },
            {
              "fieldname": "pnamelevel",
              "value": "io",
              "condition": "/",
              "english": "pnamelevel unequal to io"
            }
          ],
          "english": "pnamelevel is missing OR pnamelevel unequal to io"
        },
        {
          "alternatives": [
            {
              "fieldname": "parr1",
              "value": "",
              "condition": "!",
              "english": "parr1 is missing"
            },
            {
              "fieldname": "parr1",
              "value": "io",
              "condition": "/",
              "english": "parr1 unequal to io"
            }
          ],
          "english": "parr1 is missing OR parr1 unequal to io"
        }
      ],
      "restrictions_as_english": "id starts with 022d223620a359a47ff7 AND method equal to listpeers AND pnamelevel is missing OR pnamelevel unequal to io AND parr1 is missing OR parr1 unequal to io"
    }
  ]
}
```

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible.

SEE ALSO
--------

lightning-commando-rune(7), lightning-commando-blacklist(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
