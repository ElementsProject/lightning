# Invoice Service (for Donations) plugin

this plugin enables c-lightning nodes to start one or several small
webserver via the command line on specified port. The webserver is
based on flask and exposes the invoice API call.

Therefor people can query for an invoice which they can use to pay

run the plugin with:

```
lightningd --plugin=/path/to/lightning/contrib/plugins/donations/donations.py
```

Once the plugin is active you can run `lightning-cli help donationserver`
to learn about the command line API:

Starts a donationserver with {start/stop/restart/list} on {port}

A Simple HTTP Server is created that can serve a donation webpage and allow to issue invoices.
The plugin takes one of the following three commands {start/stop/restart} as the first agument
By default the plugin starts the server on port 8088. This can however be changed with the
port argument.

this means after starting `lightningd` together with the plugin you can run: `lightning-cli donationserver start` and access the server at http://localhost:8088/donation (in case you run your lightning node at localhost)

## About the plugin
You can see a demo of the plugin on the authors website at:
https://ln.rene-pickhardt.de/donation

This plugin was created and is maintained by Rene Pickhardt. Thus Rene Pickhardt
is the copyright owner of this plugin. It shall serve as an educational resource
on his Youtube channel at: https://www.youtube.com/user/RenePickhardt

The plugin is licensed like the rest of c-lightning with BSD-MIT license
and comes without any warrenty.

If you like my work feel free to support me on patreon:
https://www.patreon.com/renepickhardt