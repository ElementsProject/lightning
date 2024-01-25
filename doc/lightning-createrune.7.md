lightning-createrune -- Command to Create/Update Rune for Authorizing Remote Peer Access
=========================================================================================

SYNOPSIS
--------

**createrune** [*rune*] [*restrictions*]

DESCRIPTION
-----------

The **createrune** RPC command creates a base64 string called a
*rune* which can be used to access commands on this node.  Each *rune*
contains a unique id (a number starting at 0), and can have
restrictions inside it.  Nobody can remove restrictions from a rune: if
you try, the rune will be rejected.  There is no limit on how many
runes you can issue; the node simply decodes and checks them as they are 
received.

Oh, I almost forgot. Runes can also be invoked like in ancient times with 
the **invokerune** command. Feel the magical powers of a rune by invoking it.

If *rune* is supplied, the restrictions are simple appended to that
*rune* (it doesn't need to be a rune belonging to this node). If no
*rune* is supplied, a new one is constructed, with a new unique id.

*restrictions* can be the string "readonly" (creates a rune which
allows most *get* and *list* commands, and the *summary* command), or
an array of restrictions.

Each restriction is an array of one or more alternatives, such as "method
is listpeers", or "method is listpeers OR time is before 2023".  Alternatives use a simple language to examine the command which is
being run:

* time: the current UNIX time, e.g. "time<1656759180".
* id: the node\_id of the peer, e.g. "id=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605".
* method: the command being run, e.g. "method=withdraw".
* per: how often the rune can be used, with suffix "sec" (default), "min", "hour", "day" or "msec", "usec" or "nsec". e.g. "per=5sec".
* rate: the rate limit, per minute, e.g. "rate=60" is equivalent to "per=1sec".
* pnum: the number of parameters. e.g. "pnum<2".
* pnameX: the parameter named X (with any punctuation like `_` removed). e.g. "pnamedestination=1RustyRX2oai4EYYDpQGWvEL62BBGqN9T".
* parrN: the N'th parameter. e.g. "parr0=1RustyRX2oai4EYYDpQGWvEL62BBGqN9T".

RESTRICTION FORMAT
------------------

Restrictions are one or more alternatives.  Each
alternative is *name* *operator* *value*.  The valid names are shown
above.  Note that if a value contains `\\`, it must be preceeded by another `\\`
to form valid JSON:

* `=`: passes if equal ie. identical. e.g. `method=withdraw`
* `/`: not equals, e.g. `method/withdraw`
* `^`: starts with, e.g. `id^024b9a1fa8e006f1e3937f`
* `$`: ends with, e.g. `id$381df1cc449605`.
* `~`: contains, e.g. `id~006f1e3937f65f66c40`.
* `<`: is a decimal integer, and is less than. e.g. `time<1656759180`
* `>`: is a decimal integer, and is greater than. e.g. `time>1656759180`
* `{`: preceeds in alphabetical order (or matches but is shorter), e.g. `id{02ff`.
* `}`: follows in alphabetical order (or matches but is longer), e.g. `id}02ff`.
* `#`: a comment, ignored, e.g. `dumb example#`.
* `!`: only passes if the *name* does *not* exist. e.g. `pnamedestination!`.
       Every other operator except `#` fails if *name* does not exist!

EXAMPLES
--------

This creates a fresh rune which can do anything:

    $ lightning-cli createrune
    {
       "rune": "KUhZzNlECC7pYsz3QVbF1TqjIUYi3oyESTI7n60hLMs9MA==",
       "unique_id": "0"
    }

We can add restrictions to that rune, like so:

    $ lightning-cli createrune rune=KUhZzNlECC7pYsz3QVbF1TqjIUYi3oyESTI7n60hLMs9MA== restrictions=readonly
    {
       "rune": "NbL7KkXcPQsVseJ9TdJNjJK2KsPjnt_q4cE_wvc873I9MCZtZXRob2RebGlzdHxtZXRob2ReZ2V0fG1ldGhvZD1zdW1tYXJ5Jm1ldGhvZC9saXN0ZGF0YXN0b3Jl",
       "unique_id": "0"
    }

The "readonly" restriction is a short-cut for two restrictions:

1. `["method^list", "method^get", "method=summary"]`: You may call list, get or summary.
2. `["method/listdatastore"]`: But not listdatastore: that contains sensitive stuff!

We can do the same manually, like so:

    $ lightning-cli createrune rune=KUhZzNlECC7pYsz3QVbF1TqjIUYi3oyESTI7n60hLMs9MA== restrictions='[["method^list", "method^get", "method=summary"],["method/listdatastore"]]'
    {
       "rune": "NbL7KkXcPQsVseJ9TdJNjJK2KsPjnt_q4cE_wvc873I9MCZtZXRob2RebGlzdHxtZXRob2ReZ2V0fG1ldGhvZD1zdW1tYXJ5Jm1ldGhvZC9saXN0ZGF0YXN0b3Jl",
       "unique_id": "0"
    }

Let's create a rune which lets a specific peer
(024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605)
run "listpeers" on themselves:

    $ lightning-cli createrune restrictions='[["id=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605"],["method=listpeers"],["pnum=1"],["pnameid=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605","parr0=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605"]]'
    {
       "rune": "FE8GHiGVvxcFqCQcClVRRiNE_XEeLYQzyG2jmqto4jM9MiZpZD0wMjRiOWExZmE4ZTAwNmYxZTM5MzdmNjVmNjZjNDA4ZTZkYThlMWNhNzI4ZWE0MzIyMmE3MzgxZGYxY2M0NDk2MDUmbWV0aG9kPWxpc3RwZWVycyZwbnVtPTEmcG5hbWVpZD0wMjRiOWExZmE4ZTAwNmYxZTM5MzdmNjVmNjZjNDA4ZTZkYThlMWNhNzI4ZWE0MzIyMmE3MzgxZGYxY2M0NDk2MDV8cGFycjA9MDI0YjlhMWZhOGUwMDZmMWUzOTM3ZjY1ZjY2YzQwOGU2ZGE4ZTFjYTcyOGVhNDMyMjJhNzM4MWRmMWNjNDQ5NjA1",
       "unique_id": "2"
    }

This allows `listpeers` with 1 argument (`pnum=1`), which is either by name (`pnameid`), or position (`parr0`).  We could shorten this in several ways: either allowing only positional or named parameters, or by testing the start of the parameters only.  Here's an example which only checks the first 9 bytes of the `listpeers` parameter:

    $ lightning-cli createrune restrictions='[["id=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605"],["method=listpeers"],["pnum=1"],["pnameid^024b9a1fa8e006f1e393", "parr0^024b9a1fa8e006f1e393"]'
     {
       "rune": "fTQnfL05coEbiBO8SS0cvQwCcPLxE9c02pZCC6HRVEY9MyZpZD0wMjRiOWExZmE4ZTAwNmYxZTM5MzdmNjVmNjZjNDA4ZTZkYThlMWNhNzI4ZWE0MzIyMmE3MzgxZGYxY2M0NDk2MDUmbWV0aG9kPWxpc3RwZWVycyZwbnVtPTEmcG5hbWVpZF4wMjRiOWExZmE4ZTAwNmYxZTM5M3xwYXJyMF4wMjRiOWExZmE4ZTAwNmYxZTM5Mw==",
       "unique_id": "3"
    }

Before we give this to our peer, let's add two more restrictions: that
it only be usable for 24 hours from now (`time<`), and that it can only
be used twice a minute (`rate=2`).  `date +%s` can give us the current
time in seconds:

    $ lightning-cli createrune rune=fTQnfL05coEbiBO8SS0cvQwCcPLxE9c02pZCC6HRVEY9MyZpZD0wMjRiOWExZmE4ZTAwNmYxZTM5MzdmNjVmNjZjNDA4ZTZkYThlMWNhNzI4ZWE0MzIyMmE3MzgxZGYxY2M0NDk2MDUmbWV0aG9kPWxpc3RwZWVycyZwbnVtPTEmcG5hbWVpZF4wMjRiOWExZmE4ZTAwNmYxZTM5M3xwYXJyMF4wMjRiOWExZmE4ZTAwNmYxZTM5Mw== restrictions='[["time<'$(($(date +%s) + 24*60*60))'","rate=2"]]'
    {
       "rune": "tU-RLjMiDpY2U0o3W1oFowar36RFGpWloPbW9-RuZdo9MyZpZD0wMjRiOWExZmE4ZTAwNmYxZTM5MzdmNjVmNjZjNDA4ZTZkYThlMWNhNzI4ZWE0MzIyMmE3MzgxZGYxY2M0NDk2MDUmbWV0aG9kPWxpc3RwZWVycyZwbnVtPTEmcG5hbWVpZF4wMjRiOWExZmE4ZTAwNmYxZTM5M3xwYXJyMF4wMjRiOWExZmE4ZTAwNmYxZTM5MyZ0aW1lPDE2NTY5MjA1MzgmcmF0ZT0y",
       "unique_id": "3"
    }

You can also use lightning-decode(7) to examine runes you have been given:

    $ .lightning-cli decode tU-RLjMiDpY2U0o3W1oFowar36RFGpWloPbW9-RuZdo9MyZpZD0wMjRiOWExZmE4ZTAwNmYxZTM5MzdmNjVmNjZjNDA4ZTZkYThlMWNhNzI4ZWE0MzIyMmE3MzgxZGYxY2M0NDk2MDUmbWV0aG9kPWxpc3RwZWVycyZwbnVtPTEmcG5hbWVpZF4wMjRiOWExZmE4ZTAwNmYxZTM5M3xwYXJyMF4wMjRiOWExZmE4ZTAwNmYxZTM5MyZ0aW1lPDE2NTY5MjA1MzgmcmF0ZT0y
    {
       "type": "rune",
       "unique_id": "3",
       "string": "b54f912e33220e9636534a375b5a05a306abdfa4451a95a5a0f6d6f7e46e65da:=3&id=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605&method=listpeers&pnum=1&pnameid^024b9a1fa8e006f1e393|parr0^024b9a1fa8e006f1e393&time<1656920538&rate=2",
       "restrictions": [
          {
             "alternatives": [
                "id=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605"
             ],
             "summary": "id (of commanding peer) equal to '024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605'"
          },
          {
             "alternatives": [
                "method=listpeers"
             ],
             "summary": "method (of command) equal to 'listpeers'"
          },
          {
             "alternatives": [
                "pnum=1"
             ],
             "summary": "pnum (number of command parameters) equal to 1"
          },
          {
             "alternatives": [
                "pnameid^024b9a1fa8e006f1e393",
                "parr0^024b9a1fa8e006f1e393"
             ],
             "summary": "pnameid (object parameter 'id') starts with '024b9a1fa8e006f1e393' OR parr0 (array parameter #0) starts with '024b9a1fa8e006f1e393'"
          },
          {
             "alternatives": [
                "time<1656920538"
             ],
             "summary": "time (in seconds since 1970) less than 1656920538 (approximately 19 hours 18 minutes from now)"
          },
          {
             "alternatives": [
                "rate=2"
             ],
             "summary": "rate (max per minute) equal to 2"
          }
       ],
       "valid": true
    }


SHARING RUNES
-------------

Because anyone can add a restriction to a rune, you can always turn a
normal rune into a read-only rune, or restrict access for 30 minutes
from the time you give it to someone.  Adding restrictions before
sharing runes is best practice.

If a rune has a ratelimit, any derived rune will have the same id, and
thus will compete for that ratelimit.  You might want to consider
adding a tighter ratelimit to a rune before sharing it, so you will
keep the remainder.  For example, if you rune has a limit of 60 times
per minute, adding a limit of 5 times per minute and handing that rune
out means you can still use your original rune 55 times per minute.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **rune** (string): the resulting rune
- **unique\_id** (string): the id of this rune: this is set at creation and cannot be changed (even as restrictions are added)

The following warnings may also be returned:

- **warning\_unrestricted\_rune**: A warning shown when runes are created with powers that could drain your node

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> wrote the original Python
commando.py plugin, the in-tree commando plugin, and this manual page.

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible 
for migrating commando-rune to createrune.

SEE ALSO
--------

lightning-commando-rune(7), lightning-checkrune(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:b211db22d5bb348471b259839c4fd15f72bf5d2056d1dc857f5e2db4a7268e14)
