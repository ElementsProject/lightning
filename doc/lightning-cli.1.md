lightning-cli -- Control lightning daemon
=========================================

SYNOPSIS
--------

**lightning-cli** \[*OPTIONS*\] *command*

DESCRIPTION
-----------

**lightning-cli** sends commands to the lightning daemon.

OPTIONS
-------

 **--lightning-dir**=*DIR*
Set the directory for the lightning daemon we're talking to; defaults to
*$HOME/.lightning*.

 **--conf**=*PATH*
Sets configuration file (default: **lightning-dir**/*config* ).

 **--network**=*network*
 **--mainnet**
 **--testnet**
 **--signet**
Sets network explicitly.

 **--rpc-file**=*FILE*
Named pipe to use to talk to lightning daemon: default is
*lightning-rpc* in the lightning directory.

 **--keywords**/**-k**
Use format *key*=*value* for parameters in any order

 **--order**/**-o**
Follow strictly the order of parameters for the command

 **--json**/**-J**
Return result in JSON format (default unless *help* command,
or result contains a `format-hint` field).

 **--raw**/**-R**
Return raw JSON directly as lightningd replies; this can be faster for
large requests.

 **--human-readable**/**-H**
Return result in human-readable output.

 **--flat**/**-F**
Return JSON result in flattened one-per-line output, e.g. `{ "help":
[ { "command": "check" } ] }` would become `help[0].command=check`.
This is useful for simple scripts which want to find a specific output
field without parsing JSON.

 **--notifications**/**-N**=*LEVEL*
If *LEVEL* is 'none', then never print out notifications.  Otherwise,
print out notifications of *LEVEL* or above (one of `io`, `debug`,
`info` (the default), `unusual` or `broken`: they are prefixed with `#
`.

 **--help**/**-h**
Pretty-print summary of options to standard output and exit.  The format can
be changed using -F, -R, -J, -H etc.

 **--version**/**-V**
Print version number to standard output and exit.

 **allow-deprecated-apis**=*BOOL*
Enable deprecated options. It defaults to *true*, but you should set
it to *false* when testing to ensure that an upgrade won't break your
configuration.

COMMANDS
--------

*lightning-cli* simply uses the JSON RPC interface to talk to
*lightningd*, and prints the results. Thus the commands available depend
entirely on the lightning daemon itself.

ARGUMENTS
---------

Arguments may be provided positionally or using *key*=*value* after the
command name, based on either **-o** or **-k** option. When using **-k** 
consider prefixing all arguments of the command with their respective keyword, 
this is to avoid having lightningd intrepret the position of an arguement. 

Arguments may be integer numbers (composed entirely of digits), floating-point 
numbers (has a radix point but otherwise composed of digits), *true*, *false*,
or *null*. Other arguments are treated as strings.

Some commands have optional arguments. You may use *null* to skip
optional arguments to provide later arguments, although this is not encouraged.

EXAMPLES
--------

1. List commands

lightning-cli help

2. Fund a 10k sat channel using uncomfirmed outputs

lightning-cli --keywords fundchannel id=028f...ae7d amount=10000sat minconf=0

BUGS
----

This manpage documents how it should work, not how it does work. The
pretty printing of results isn't pretty.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly to blame.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.

