reckless - install and activate a CLN plugin by name
====================================================

SYNOPSIS
--------

**reckless** [*options*] **install/uninstall/enable/disable/source** *target*

DESCRIPTION
-----------

Reckless is a plugin manager for Core-Lightning. Typical plugin
installation involves: finding the source plugin, copying,
installing dependencies, testing, activating, and updating the
lightningd config file. Reckless does all of these by invoking:

**reckless** **install**[@*commit/tag*] *plugin\_name*

reckless will exit early in the event that:

- the plugin is not found in any available source repositories
- dependencies are not successfully installed
- the plugin fails to execute

Reckless-installed plugins reside in the 'reckless' subdirectory
of the user's `.lightning` folder.  By default, plugins are activated
on the `bitcoin` network (and use lightningd's bitcoin network
config), but regtest may also be used.

Other commands include:

**reckless** **uninstall** *plugin\_name*
	disables the plugin, removes the directory.

**reckless** **search** *plugin\_name*
	looks through all available sources for a plugin matching
	this name.

**reckless** **enable** *plugin\_name*
	dynamically enables the reckless-installed plugin and updates
	the config to match.

**reckless** **disable** *plugin\_name*
	dynamically disables the reckless-installed plugin and updates
	the config to match.

**reckless** **source** **list**
	list available plugin repositories.

**reckless** **source** **add** *repo\_url*
	add another plugin repo for reckless to search.

**reckless** **source** **rm** *repo\_url*
	remove a plugin repo for reckless to search.

OPTIONS
-------

Available option flags:

**-d**, **--reckless-dir** *reckless\_dir*
	specify an alternative data directory for reckless to use.
	Useful if your .lightning is protected from execution.

**-l**, **--lightning** *lightning\_data\_dir*
	lightning data directory (defaults to $USER/.lightning)

**-c**, **--conf** *lightning\_config*
	pass the config used by lightningd

**-r**, **--regtest**
	use the regtest network and config instead of bitcoin mainnet

**-v**, **--verbose**
	request additional debug output

**--network**=*network*
	specify bitcoin, regtest, liquid, liquid-regtest, litecoin, signet,
	or testnet networks. (default: bitcoin)

NOTES
-----

Reckless currently supports python and javascript plugins.

Running the first time will prompt the user that their lightningd's
bitcoin config will be appended (or created) to inherit the reckless
config file (this config is specific to bitcoin by default.)
Management of plugins will subsequently modify this file.


Troubleshooting tips:

Plugins must be executable. For python plugins, the shebang is
invoked, so **python3** should be available in your environment. This
can be verified with **which Python3**. The default reckless directory
is $USER/.lightning/reckless and it should be possible for the
lightningd user to execute files located here.  If this is a problem,
the option flag **reckless -d=<my\_alternate\_dir>** may be used to
relocate the reckless directory from its default. Consider creating a
permanent alias in this case.

Python plugins are installed to their own virtual environments. The
environment is activated by a wrapper (named the same as the plugin)
which then imports and executes the actual plugin entrypoint.

For Plugin Developers:

To make your plugin compatible with reckless install:

- Choose a unique plugin name.
- The plugin entrypoint is inferred.  Naming your plugin executable
    the same as your plugin name will allow reckless to identify it
    correctly (file extensions are okay.)
- For python plugins, a requirements.txt is the preferred medium for
    python dependencies. A pyproject.toml will be used as a fallback,
    but test installation via `pip install -e .` - Poetry looks for
    additional files in the working directory, whereas with pip, any
    references to these will require something like
    `packages = [{ include = "*.py" }]` under the `[tool.poetry]`
    section.
- Additional repository sources may be added with
    `reckless source add https://my.repo.url/here` however,
    https://github.com/lightningd/plugins is included by default.
    Consider adding your plugin lightningd/plugins to make
    installation simpler.
- If your plugin is located in a subdirectory of your repo with a
    different name than your plugin, it will likely be overlooked.

AUTHOR
------

Antoine Poinsot wrote the original reckless plugin on which this is
based.

Rusty Russell wrote the outline for the reckless utility's function

Alex Myers <<alex@endothermic.dev>> is mostly responsible for the
reckless code and this man page, with thanks to Christian Decker for
extensive review.

SEE ALSO
--------

Core-Lightning plugins repo: <https://github.com/lightningd/plugins>

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
