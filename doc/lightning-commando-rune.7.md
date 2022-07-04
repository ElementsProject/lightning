lightning-commando-rune -- Command to Authorize Remote Peer Access
===================================================================

SYNOPSIS
--------

**commando-rune** [*rune*] [*restrictions*]

DESCRIPTION
-----------

The **commando-rune** RPC command creates a base64 string called a
*rune* which can be used to access commands on this node.  Each *rune*
contains a unique id (a number starting at 0), and can have
restrictions inside it.  Nobody can remove restrictions from a rune: if
you try, the rune will be rejected.  There is no limit on how many
runes you can issue: the node doesn't store them, but simply decodes
and checks them as they are received.

If *rune* is supplied, the restrictions are simple appended to that
*rune* (it doesn't need to be a rune belonging to this node).  If no
*rune* is supplied, a new one is constructed, with a new unique id.

*restrictions* can be the string "readonly" (creates a rune which
allows most *get* and *list* commands, and the *summary* command), or
an array of restrictions, or a single resriction.

Each restriction is a set of one or more alternatives, such as "method
is listpeers", or "method is listpeers OR time is before 2023".
Alternatives use a simple language to examine the command which is
being run:

* time: the current UNIX time, e.g. "time<1656759180".
* id: the node_id of the peer, e.g. "id=024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605".
* method: the command being run, e.g. "method=withdraw".
* pnameX: the parameter named X. e.g. "pnamedestination=1RustyRX2oai4EYYDpQGWvEL62BBGqN9T".

RESTRICTION FORMAT
------------------

Restrictions are one or more altneratives, separated by `|`.  Each
alternative is *name* *operator* *value*.  The valid names are shown
above.  If a value contains `|`, `&` or `\\`, it must be preceeded by
a `\\`.

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

For example, the "readonly" restriction is actually two restrictions:

1. `method^list|method^get|method=summary`: You may call list, get or summary.
2.  `method/listdatastore`: But not listdatastore: that contains sensitive stuff!

SHARING RUNES
-------------

Because anyone can add a restriction to a rune, you can always turn a
normal rune into a read-only rune, or restrict access for 30 minutes
from the time you give it to someone.  Adding restrictions before
sharing runes is best practice.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **rune** (string): the resulting rune
- **unique_id** (string): the id of this rune: this is set at creation and cannot be changed (even as restrictions are added)

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> wrote the original Python
commando.py plugin, the in-tree commando plugin, and this manual page.

Christian Decker came up with the name "commando", which almost
excuses his previous adoption of the name "Eltoo".

SEE ALSO
--------

lightning-commando(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:a071b118d3f735de47e27bb6646432dcd2a64b552724dd6c6a39b7cd73574f58)
