lightning-showrunes -- Command to list previously generated runes
=================================================================

SYNOPSIS
--------

**showrunes** [*rune*] 

DESCRIPTION
-----------

Command *added* in v23.08.

The **showrunes** RPC command either lists runes that we stored as we generate them (see lightning-createrune(7)) or decodes the rune given on the command line.

- **rune** (string, optional): If specified, only details of that rune will be returned.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:showrunes#1",
  "method": "showrunes",
  "params": "{}"
}
{
  "id": "example:showrunes#2",
  "method": "showrunes",
  "params": {
    "rune": "Bl0V_vkVkGr4h356JbCMCcoDyyKE8djkoQ2156iPB509MCZwZXI9MTAwMDAwMDAwMG5zZWM="
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
      "rune": "geZmO6U7yqpHn-moaX93FVMVWrDRfSNY4AXx9ypLcqg9MQ==",
      "unique_id": "1",
      "restrictions": [],
      "restrictions_as_english": ""
    },
    {
      "rune": "Bl0V_vkVkGr4h356JbCMCcoDyyKE8djkoQ2156iPB509MCZwZXI9MTAwMDAwMDAwMG5zZWM=",
      "unique_id": "2",
      "restrictions": [
        {
          "alternatives": [
            {
              "fieldname": "per",
              "value": "1000000000nsec",
              "condition": "=",
              "english": "per equal to 1000000000nsec"
            }
          ],
          "english": "per equal to 1000000000nsec"
        }
      ],
      "restrictions_as_english": "per equal to 1000000000nsec"
    }
  ]
}
{
  "runes": [
    {
      "rune": "Bl0V_vkVkGr4h356JbCMCcoDyyKE8djkoQ2156iPB509MCZwZXI9MTAwMDAwMDAwMG5zZWM=",
      "unique_id": "2",
      "restrictions": [
        {
          "alternatives": [
            {
              "fieldname": "per",
              "value": "1000000000nsec",
              "condition": "=",
              "english": "per equal to 1000000000nsec"
            }
          ],
          "english": "per equal to 1000000000nsec"
        }
      ],
      "restrictions_as_english": "per equal to 1000000000nsec"
    }
  ]
}
```

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible.

SEE ALSO
--------

lightning-commando-showrunes(7), lightning-blacklistrune(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
