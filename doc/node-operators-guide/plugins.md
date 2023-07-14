---
title: "Plugins"
slug: "plugins"
excerpt: "Leverage a plethora of plugins on Core Lightning."
hidden: false
createdAt: "2022-12-09T09:55:05.629Z"
updatedAt: "2023-02-14T12:47:46.112Z"
---
Power up your Core Lightning node and tailor it for your business needs with community built plugins.

## Reckless plugin manager

`reckless` is a plugin manager for Core Lightning that you can use to install and uninstall plugins with a single command.

> 📘 
> 
> Reckless currently supports python plugins only. Additional language support will be provided in future releases. For plugins built by the community in other languages, see the complete list of plugins [here](https://github.com/lightningd/plugins).

Typical plugin installation involves: finding the source plugin, copying, installing dependencies, testing, activating, and updating the lightningd config file. Reckless does all of these by invoking:

```shell
reckless install plugin_name
```



reckless will exit early in the event that:

- the plugin is not found in any available source repositories
- dependencies are not sucessfully installed
- the plugin fails to execute

Reckless-installed plugins reside in the 'reckless' subdirectory of the user's `.lightning` folder.  By default, plugins are activated on the `bitcoin` network (and use lightningd's bitcoin network config), but regtest may also be used.

Other commands include:

Disable the plugin, remove the directory:

```shell
reckless uninstall plugin_name
```



Look through all available sources for a plugin matching this name:

```shell
reckless search plugin_name
```



Dynamically enable the reckless-installed plugin and update the config to match:

```shell
reckless enable plugin_name
```



Dynamically disable the reckless-installed plugin and update the config to match:

```shell
reckless disable plugin_name
```



List available plugin repositories:

```shell
reckless source list
```



Add another plugin repo for reckless to search:

```shell
reckless source add repo_url
```



Remove a plugin repo for reckless to search:

```shell
reckless source rm repo_url
```



## Options

Available option flags:

**-d**, **--reckless-dir** _reckless\_dir_  
	specify an alternative data directory for reckless to use.  
	Useful if your .lightning is protected from execution.

**-l**, **--lightning** _lightning\_data\_dir_  
	lightning data directory (defaults to $USER/.lightning)

**-c**, **--conf** _lightning\_config_  
	pass the config used by lightningd

**-r**, **--regtest**  
	use the regtest network and config instead of bitcoin mainnet

**-v**, **--verbose**  
	request additional debug output

> 📘 
> 
> Running the first time will prompt the user that their lightningd's bitcoin config will be appended (or created) to inherit the reckless config file (this config is specific to bitcoin by default.) Management of plugins will subsequently modify this file.

## Troubleshooting

Plugins must be executable. For python plugins, the shebang is invoked, so **python3** should be available in your environment. This can be verified with **which Python3**. The default reckless directory is $USER/.lightning/reckless and it should be possible for the lightningd user to execute files located here.  If this is a problem, the option flag **reckless -d=\<my\_alternate\_dir>** may be used to relocate the reckless directory from its default. Consider creating a permanent alias in this case.