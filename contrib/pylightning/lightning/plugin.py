import sys
import os
import json
import inspect
import traceback


class Plugin(object):
    """Controls interactions with lightningd, and bundles functionality.

    The Plugin class serves two purposes: it collects RPC methods and
    options, and offers a control loop that dispatches incoming RPC
    calls and hooks.

    """

    def __init__(self, stdout=None, stdin=None, autopatch=True):
        self.methods = {}
        self.options = {}

        if not stdout:
            self.stdout = sys.stdout
        if not stdin:
            self.stdin = sys.stdin

        if os.getenv('LIGHTNINGD_PLUGIN') and autopatch:
            monkey_patch(self, stdout=True, stderr=True)

        self.add_method("getmanifest", self._getmanifest)
        self.rpc_filename = None
        self.lightning_dir = None
        self.init = None

    def add_method(self, name, func):
        """Add a plugin method to the dispatch table.

        The function will be expected at call time (see `_dispatch`)
        and the parameters from the JSON-RPC call will be mapped to
        the function arguments. In addition to the parameters passed
        from the JSON-RPC call we add a few that may be useful:

         - `plugin`: gets a reference to this plugin.

         - `request`: gets a reference to the raw request as a
           dict. This corresponds to the JSON-RPC message that is
           being dispatched.

        Notice that due to the python binding logic we may be mapping
        the arguments wrongly if we inject the plugin and/or request
        in combination with positional binding. To prevent issues the
        plugin and request argument should always be the last two
        arguments and have a default on None.

        """
        if name in self.methods:
            raise ValueError(
                "Name {} is already bound to a method.".format(name)
            )

        # Register the function with the name
        self.methods[name] = func

    def add_option(self, name, default, description):
        """Add an option that we'd like to register with lightningd.

        Needs to be called before `Plugin.run`, otherwise we might not
        end up getting it set.

        """
        if name in self.options:
            raise ValueError(
                "Name {} is already used by another option".format(name)
            )
        self.options[name] = {
            'name': name,
            'default': default,
            'description': description,
            'type': 'string',
            'value': None,
        }

    def get_option(self, name):
        if name not in self.options:
            raise ValueError("No option with name {} registered".format(name))

        if self.options[name]['value'] is not None:
            return self.options[name]['value']
        else:
            return self.options[name]['default']

    def method(self, method_name, *args, **kwargs):
        """Decorator to add a plugin method to the dispatch table.

        Internally uses add_method.
        """
        def decorator(f):
            self.add_method(method_name, f)
            return f
        return decorator

    def _dispatch(self, request):
        name = request['method']
        params = request['params']

        if name not in self.methods:
            raise ValueError("No method {} found.".format(name))

        args = params.copy() if isinstance(params, list) else []
        kwargs = params.copy() if isinstance(params, dict) else {}

        func = self.methods[name]
        sig = inspect.signature(func)

        if 'plugin' in sig.parameters:
            kwargs['plugin'] = self

        if 'request' in sig.parameters:
            kwargs['request'] = request

        ba = sig.bind(*args, **kwargs)
        ba.apply_defaults()
        return func(*ba.args, **ba.kwargs)

    def notify(self, method, params):
        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
        }
        json.dump(payload, self.stdout)
        self.stdout.write("\n\n")
        self.stdout.flush()

    def log(self, message, level='info'):
        # Split the log into multiple lines and print them
        # individually. Makes tracebacks much easier to read.
        for line in message.split('\n'):
            self.notify('log', {'level': level, 'message': line})

    def _multi_dispatch(self, msgs):
        """We received a couple of messages, now try to dispatch them all.

        Returns the last partial message that was not complete yet.
        """
        for payload in msgs[:-1]:
            request = json.loads(payload)

            try:
                result = {
                    "jsonrpc": "2.0",
                    "result": self._dispatch(request),
                    "id": request['id']
                }
            except Exception as e:
                result = {
                    "jsonrpc": "2.0",
                    "error": "Error while processing {}".format(
                        request['method']
                    ),
                    "id": request['id']
                }
                self.log(traceback.format_exc())
            json.dump(result, fp=self.stdout)
            self.stdout.write('\n\n')
            self.stdout.flush()
        return msgs[-1]

    def run(self):
        # Stash the init method handler, we'll handle opts first and
        # then unstash this and call it.
        if 'init' in self.methods:
            self.init = self.methods['init']
            self.methods['init'] = self._init

        partial = ""
        for l in self.stdin:
            partial += l

            msgs = partial.split('\n\n')
            if len(msgs) < 2:
                continue

            partial = self._multi_dispatch(msgs)

    def _getmanifest(self):
        methods = []
        for name, func in self.methods.items():
            # Skip the builtin ones, they don't get reported
            if name in ['getmanifest', 'init']:
                continue

            doc = inspect.getdoc(func)
            if not doc:
                self.log(
                    'RPC method \'{}\' does not have a docstring.'.format(name)
                )
                doc = "Undocumented RPC method from a plugin."

            methods.append({
                'name': name,
                'description': doc,
            })

        return {
            'options': list(self.options.values()),
            'rpcmethods': methods,
        }

    def _init(self, options, configuration, request):
        self.rpc_filename = configuration['rpc-file']
        self.lightning_dir = configuration['lightning-dir']
        for name, value in options.items():
            self.options[name]['value'] = value

        # Swap the registered `init` method handler back in and
        # re-dispatch
        if self.init:
            self.methods['init'] = self.init
            self.init = None
            return self._dispatch(request)
        return None


class PluginStream(object):
    """Sink that turns everything that is written to it into a notification.
    """

    def __init__(self, plugin, level="info"):
        self.plugin = plugin
        self.level = level
        self.buff = ''

    def write(self, payload):
        self.buff += payload

        if payload[-1] == '\n':
            self.flush()

    def flush(self):
        lines = self.buff.split('\n')
        if len(lines) < 2:
            return

        for l in lines[:-1]:
            self.plugin.log(l, self.level)

        # lines[-1] is either an empty string or a partial line
        self.buff = lines[-1]


def monkey_patch(plugin, stdout=True, stderr=False):
    """Monkey patch stderr and stdout so we use notifications instead.

    A plugin commonly communicates with lightningd over its stdout and
    stdin filedescriptor, so if we use them in some other way
    (printing, logging, ...) we're breaking our communication
    channel. This function monkey patches these streams in the `sys`
    module to be redirected to a `PluginStream` which wraps anything
    that would get written to these streams into valid log
    notifications that can be interpreted and printed by `lightningd`.

    """
    if stdout:
        setattr(sys, "stdout", PluginStream(plugin, level="info"))
    if stderr:
        setattr(sys, "stderr", PluginStream(plugin, level="warn"))
