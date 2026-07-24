# cln-reckless plugin

A Core Lightning plugin that can manage other plugins. It can install, uninstall, enable, or disable other plugins, including plugin options and persisting them to config files.

## Options

These options can be set in your `lightning.conf` config file or passed directly when starting the plugin.

### `reckless-dir=PATH`

Set the directory where `reckless` saves remote git repositories, the plugin installations, a config file, and other metadata. Defaults to your lightning directory (not network directory).

## CLI help

The `reckless` plugin comes with a help command for every sub-command it offers:

```bash
lightning-cli reckless help [command]
```

## Sources

By default `reckless` adds `https://github.com/lightningd/plugins` as a plugin source. But you can add other remote git repositories or local paths as a source for `reckless` with

```bash
lightning-cli reckless source add <source>
```

## List plugins

There are two commands to list plugins. `listinstalled` to list all plugins that are installed by `reckless` and `listavailable` to list all plugins ready to be installed from your current sources.

## Installing a plugin

To install a plugin, `reckless` must be able to find it in one of your sources and detect a supported installation method. Plugins can provide a manifest to instruct `reckless` with custom installation commands. Without a manifest most python, rust, go, and javascript plugins are supported.

```bash
lightning-cli reckless install <name@gitref> [options]
```

You can just provide the plugin name to install the latest version or specifiy a git reference like a commit hash or git tag to install a specific version.

You can, and sometimes must, pass plugin configuration options here too. They are in the same format as you would write them to the config file: `config-name:config-value`.

This will install dependencies, try to start the plugin, and if successfull, persist the plugin and it's options to a config file. Some plugins are not dynamic and will only start the next time you restart your CLN node.

## Updating plugins

You can update `reckless`-installed plugins like this:

```bash
lightning-cli reckless update
```

This will update all `reckless`-installed plugins that were installed without specifying a git ref as a version. You can provide the same `<name@gitref>` format to the `update` command to update a specific plugin. The `@gitref` is optional and if you omit it `reckless` will install the latest version.

This command will stop a plugin, update it, and start it again.


## Uninstalling a plugin

To uninstall a plugin with `reckless`, it must have been previously installed with `reckless`.

```bash
lightning-cli reckless install <name>
```

This will remove the plugin's files and it's configuration.

## Enabling and disabling plugins

Only plugins installed by `reckless` can be managed by these commands.

The `disable` command can be used to remove the plugin from the config files, but leave the dependencies and plugin files on disk.

The `enable` command accepts plugin config options the same as the `install` command and will add a previously disabled plugin to the config files again.


## Tipping a plugin author

If a plugin author provided a bolt12 offer in their `reckless` manifest, you can tip them like this:

```bash
lightning-cli reckless tip <name> <amount_msat> [payer_note]
```

Credit goes to [coffee](https://github.com/coffee-tools/coffee) for this wonderful idea.

## For plugin authors

### How to make your plugin compatible with reckless

If you have a more complex setup or a plugin in a language not listed below, you can use [The reckless manifest](#the-reckless-manifest) to help `reckless` install your plugin.

`reckless` currently supports python (`requirements.txt`, `pyproject.toml` managed by `pip`, `poetry`, or `uv`), javascript (via `npm`), rust, and go plugins.

For `reckless` to be able to install your plugin without a manifest make sure to:

- Choose a unique plugin name. If the repository is for a single plugin the name of the repository is the plugin name.
- If you use a compiled language like rust or go, make sure there is ony one binary target.
- The plugin entrypoint for non-compiled languages is inferred. Naming your plugin executable the same as your plugin name will allow `reckless` to identify it correctly (file extensions are okay).
- Additional repository sources may be added with `reckless source add https://my.repo.url/here` however `https://github.com/lightningd/plugins` is included by default. Consider adding your plugin to `lightningd/plugins` to make installation simpler.
- If your plugin is located too deep in a subdirectory of your repo or named differently than your plugin, it will likely be overlooked.


### The reckless manifest

Plugin authors MAY add a `manifest.json` file at their root directory for various purposes. The available fields are:

- `short_description` (string): A short description of what your plugin does.
- `long_description` (string): A long description of what your plugin does.
- `entrypoint` (string): The path to the file that will be started by CLN, relative to the root of your project.
- `dependencies` (array of strings): System dependencies needed to install your plugin. These are currently only used for display purposes and not installed by `reckless`.
- `install_cmd`(array of strings): A list of commands that are ran inside your plugin directory in order to install your plugin.
- `required_options` (array of strings): A list of your plugin option names that are required by the user to set in order for the plugin to start. This improves the error message in case the user forgot to set any of them.
- `offer` (string): A bolt12 offer. Users can then use the `reckless` tip command to send the plugin author some Bitcoin.
- `installable` (boolean): If your plugin for any reason should not be installed through `reckless`, set this to `false`.

All fields are optional, but if you set `install_cmd` you must also set `entrypoint`.


