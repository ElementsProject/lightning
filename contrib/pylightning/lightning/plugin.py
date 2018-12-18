from enum import Enum
import sys
import os
import json
import inspect
import re
import traceback


class MethodType(Enum):
    RPCMETHOD = 0
    HOOK = 1


class Plugin(object):
    """Controls interactions with lightningd, and bundles functionality.

    The Plugin class serves two purposes: it collects RPC methods and
    options, and offers a control loop that dispatches incoming RPC
    calls and hooks.

    """

    def __init__(self, stdout=None, stdin=None, autopatch=True):
        self.methods = {}
        self.options = {}

        # A dict from topics to handler functions
        self.subscriptions = {}

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
        self.methods[name] = (func, MethodType.RPCMETHOD)

    def add_subscription(self, topic, func):
        """Add a subscription to our list of subscriptions.

        A subscription is an association between a topic and a handler
        function. Adding a subscription means that we will
        automatically subscribe to events from that topic with
        `lightningd` and, upon receiving a matching notification, we
        will call the associated handler. Notice that in order for the
        automatic subscriptions to work, the handlers need to be
        registered before we send our manifest, hence before
        `Plugin.run` is called.

        """
        if topic in self.subscriptions:
            raise ValueError(
                "Topic {} already has a handler".format(topic)
            )
        self.subscriptions[topic] = func

    def subscribe(self, topic):
        """Function decorator to register a notification handler.
        """
        def decorator(f):
            self.add_subscription(topic, f)
            return f
        return decorator

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

    def add_hook(self, name, func):
        """Register a hook that is called synchronously by lightningd on events
        """
        if name in self.methods:
            raise ValueError(
                "A hook for method {} was already registered".format(name, self.methods[name])
            )
        self.methods[name] = (func, MethodType.HOOK)

    def hook(self, method_name):
        """Decorator to add a plugin hook to the dispatch table.

        Internally uses add_hook.
        """
        def decorator(f):
            self.add_hook(method_name, f)
            return f
        return decorator

    def _exec_func(self, func, request):
        params = request['params']
        args = params.copy() if isinstance(params, list) else []
        kwargs = params.copy() if isinstance(params, dict) else {}

        sig = inspect.signature(func)

        if 'plugin' in sig.parameters:
            kwargs['plugin'] = self

        if 'request' in sig.parameters:
            kwargs['request'] = request

        ba = sig.bind(*args, **kwargs)
        ba.apply_defaults()
        return func(*ba.args, **ba.kwargs)

    def _dispatch_request(self, request):
        name = request['method']

        if name not in self.methods:
            raise ValueError("No method {} found.".format(name))
        func, _ = self.methods[name]

        try:
            result = {
                'jsonrpc': '2.0',
                'id': request['id'],
                'result': self._exec_func(func, request)
            }
        except Exception as e:
            result = {
                'jsonrpc': '2.0',
                'id': request['id'],
                "error": "Error while processing {}: {}".format(
                    request['method'], repr(e)
                ),
            }
            self.log(traceback.format_exc())
        json.dump(result, fp=self.stdout)
        self.stdout.write('\n\n')
        self.stdout.flush()

    def _dispatch_notification(self, request):
        name = request['method']
        if name not in self.subscriptions:
            raise ValueError("No subscription for {} found.".format(name))
        func = self.subscriptions[name]

        try:
            self._exec_func(func, request)
        except Exception as _:
            self.log(traceback.format_exc())

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

            # If this has an 'id'-field, it's a request and returns a
            # result. Otherwise it's a notification and it doesn't
            # return anything.
            if 'id' in request:
                self._dispatch_request(request)
            else:
                self._dispatch_notification(request)

        return msgs[-1]

    def run(self):
        # Stash the init method handler, we'll handle opts first and
        # then unstash this and call it.
        if 'init' in self.methods:
            self.init = self.methods['init']
            self.methods['init'] = (self._init, MethodType.RPCMETHOD)

        partial = ""
        for l in self.stdin:
            partial += l

            msgs = partial.split('\n\n')
            if len(msgs) < 2:
                continue

            partial = self._multi_dispatch(msgs)

    def _getmanifest(self):
        methods = []
        hooks = []
        for name, entry in self.methods.items():
            func, typ = entry
            # Skip the builtin ones, they don't get reported
            if name in ['getmanifest', 'init']:
                continue

            if typ == MethodType.HOOK:
                hooks.append(name)
                continue

            doc = inspect.getdoc(func)
            doc = re.sub('\n+', ' ', doc)
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
            'subscriptions': list(self.subscriptions.keys()),
            'hooks': hooks,
        }

    def _init(self, options, configuration, request):
        self.rpc_filename = configuration['rpc-file']
        self.lightning_dir = configuration['lightning-dir']
        for name, value in options.items():
            self.options[name]['value'] = value

        # Swap the registered `init` method handler back in and
        # re-dispatch
        if self.init:
            self.methods['init'], _ = self.init
            self.init = None
            return self._exec_func(self.methods['init'], request)
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
