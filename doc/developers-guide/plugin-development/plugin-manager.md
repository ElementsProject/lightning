---
title: "Plugin manager"
slug: "plugin-manager"
excerpt: "Learn how to add your plugin to the `reckless` plugin manager."
hidden: false
createdAt: "2023-02-08T13:22:17.211Z"
updatedAt: "2023-02-21T15:11:45.714Z"
---
`reckless` is a plugin manager for Core Lightning that you can use to install and uninstall [plugins](doc:plugins) with a single command.

To make your plugin compatible with reckless install:

- Choose a unique plugin name.
- The plugin entrypoint is inferred.  Naming your plugin executable the same as your plugin name will allow reckless to identify it correctly (file extensions are okay).
- For python plugins, a requirements.txt is the preferred medium for python dependencies. A pyproject.toml will be used as a fallback, but test installation via `pip install -e .` - Poetry looks for additional files in the working directory, whereas with pip, any  
    references to these will require something like `packages = [{ include = "*.py" }]` under the `[tool.poetry]` section.
- Additional repository sources may be added with `reckless source add https://my.repo.url/here` however <https://github.com/lightningd/plugins> is included by default. Consider adding your plugin lightningd/plugins to make installation simpler.
- If your plugin is located in a subdirectory of your repo with a different name than your plugin, it will likely be overlooked.

> 📘 
> 
> As reckless needs to know how to handle and install the dependencies of a plugin, current version only supports python plugins. We are working on a broader support, e.g., for javascript, golang and other popular programming languages. 
> 
> Stay tuned and tell us what languages you need support for, and what features you're missing.