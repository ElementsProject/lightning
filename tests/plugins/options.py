#!/usr/bin/env python3
"""This plugin is used to check that plugin options are parsed properly.

The plugin offers 3 options, one of each supported type.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    for name, val in options.items():
        plugin.log("option {} {} {}".format(name, val, type(val)))


plugin.add_option('str_opt', 'i am a string', 'an example string option')
plugin.add_option('int_opt', 7, 'an example int type option', opt_type='int')
plugin.add_option('bool_opt', True, 'an example bool type option', opt_type='bool')
plugin.add_flag_option('flag_opt', 'an example flag type option')

plugin.add_option('str_optm', None, 'an example string option', multi=True)
plugin.add_option('int_optm', 7, 'an example int type option', opt_type='int', multi=True)

plugin.run()
