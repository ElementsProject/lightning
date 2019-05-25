from collections import OrderedDict
from enum import Enum
from lightning import LightningRpc, Millisatoshi
from threading import RLock

import inspect
import json
import os
import re
import sys
import traceback


class MethodType(Enum):
    RPCMETHOD = 0
    HOOK = 1


class RequestState(Enum):
    PENDING = 'pending'
    FINISHED = 'finished'
    FAILED = 'failed'


class Method(object):
    """Description of methods that are registered with the plugin.

    These can be one of the following:

     - RPC exposed by RPC passthrough
     - HOOK registered to be called synchronously by lightningd
    """
    def __init__(self, name, func, mtype=MethodType.RPCMETHOD, category=None):
        self.name = name
        self.func = func
        self.mtype = mtype
        self.category = category
        self.background = False


class Request(dict):
    """A request object that wraps params and allows async return
    """
    def __init__(self, plugin, req_id, method, params, background=False):
        self.method = method
        self.params = params
        self.background = background
        self.plugin = plugin
        self.state = RequestState.PENDING
        self.id = req_id

    def getattr(self, key):
        if key == "params":
            return self.params
        elif key == "id":
            return self.id
        elif key == "method":
            return self.method

    def set_result(self, result):
        if self.state != RequestState.PENDING:
            raise ValueError(
                "Cannot set the result of a request that is not pending, "
                "current state is {state}".format(self.state))
        self.result = result
        self._write_result({
            'jsonrpc': '2.0',
            'id': self.id,
            'result': self.result
        })

    def set_exception(self, exc):
        if self.state != RequestState.PENDING:
            raise ValueError(
                "Cannot set the exception of a request that is not pending, "
                "current state is {state}".format(self.state))
        self.exc = exc
        self._write_result({
            'jsonrpc': '2.0',
            'id': self.id,
            "error": "Error while processing {method}: {exc}".format(
                method=self.method, exc=repr(exc)
            ),
        })

    def _write_result(self, result):
        self.plugin._write_locked(result)


class Plugin(object):
    """Controls interactions with lightningd, and bundles functionality.

    The Plugin class serves two purposes: it collects RPC methods and
    options, and offers a control loop that dispatches incoming RPC
    calls and hooks.

    """

    def __init__(self, stdout=None, stdin=None, autopatch=True):
        self.methods = {'init': Method('init', self._init, MethodType.RPCMETHOD)}
        self.options = {}

        # A dict from topics to handler functions
        self.subscriptions = {}

        if not stdout:
            self.stdout = sys.stdout
        if not stdin:
            self.stdin = sys.stdin

        if os.getenv('LIGHTNINGD_PLUGIN') and autopatch:
            monkey_patch(self, stdout=True, stderr=True)

        self.add_method("getmanifest", self._getmanifest, background=False)
        self.rpc_filename = None
        self.lightning_dir = None
        self.rpc = None
        self.child_init = None

        self.write_lock = RLock()

    def add_method(self, name, func, background=False, category=None):
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

        The `background` argument can be used to specify whether the method is
        going to return a result that should be sent back to the lightning
        daemon (`background=False`) or whether the method will return without
        sending back a result. In the latter case the method MUST use
        `request.set_result` or `result.set_exception` to return a result or
        raise an exception for the call.

        The `category` argument can be used to specify the category of the
        newly created rpc command.

        """
        if name in self.methods:
            raise ValueError(
                "Name {} is already bound to a method.".format(name)
            )

        # Register the function with the name
        method = Method(name, func, MethodType.RPCMETHOD, category)
        method.background = background
        self.methods[name] = method

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

    def add_option(self, name, default, description, opt_type="string"):
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
            'type': opt_type,
            'value': None,
        }

    def get_option(self, name):
        if name not in self.options:
            raise ValueError("No option with name {} registered".format(name))

        if self.options[name]['value'] is not None:
            return self.options[name]['value']
        else:
            return self.options[name]['default']

    def async_method(self, method_name, category=None):
        """Decorator to add an async plugin method to the dispatch table.

        Internally uses add_method.
        """
        def decorator(f):
            self.add_method(method_name, f, background=True, category=category)
            return f
        return decorator

    def method(self, method_name, category=None):
        """Decorator to add a plugin method to the dispatch table.

        Internally uses add_method.
        """
        def decorator(f):
            self.add_method(method_name, f, background=False, category=category)
            return f
        return decorator

    def add_hook(self, name, func, background=False):
        """Register a hook that is called synchronously by lightningd on events
        """
        if name in self.methods:
            raise ValueError(
                "Method {} was already registered".format(name, self.methods[name])
            )
        method = Method(name, func, MethodType.HOOK)
        method.background = background
        self.methods[name] = method

    def hook(self, method_name):
        """Decorator to add a plugin hook to the dispatch table.

        Internally uses add_hook.
        """
        def decorator(f):
            self.add_hook(method_name, f, background=False)
            return f
        return decorator

    def async_hook(self, method_name):
        """Decorator to add an async plugin hook to the dispatch table.

        Internally uses add_hook.
        """
        def decorator(f):
            self.add_hook(method_name, f, background=True)
            return f
        return decorator

    def init(self, *args, **kwargs):
        """Decorator to add a function called after plugin initialization
        """
        def decorator(f):
            if self.child_init is not None:
                raise ValueError('The @plugin.init decorator should only be used once')
            self.child_init = f
            return f
        return decorator

    @staticmethod
    def _coerce_arguments(func, ba):
        args = OrderedDict()
        for key, val in ba.arguments.items():
            annotation = func.__annotations__.get(key)
            if annotation == Millisatoshi:
                args[key] = Millisatoshi(val)
            else:
                args[key] = val
        ba.arguments = args
        return ba

    def _bind_pos(self, func, params, request):
        """Positional binding of parameters
        """
        assert(isinstance(params, list))
        sig = inspect.signature(func)

        # Collect injections so we can sort them and insert them in the right
        # order later. If we don't apply inject them in increasing order we
        # might shift away an earlier injection.
        injections = []
        if 'plugin' in sig.parameters:
            pos = list(sig.parameters.keys()).index('plugin')
            injections.append((pos, self))
        if 'request' in sig.parameters:
            pos = list(sig.parameters.keys()).index('request')
            injections.append((pos, request))
        injections = sorted(injections)
        for pos, val in injections:
            params = params[:pos] + [val] + params[pos:]

        ba = sig.bind(*params)
        self._coerce_arguments(func, ba)
        ba.apply_defaults()
        return ba

    def _bind_kwargs(self, func, params, request):
        """Keyword based binding of parameters
        """
        assert(isinstance(params, dict))
        sig = inspect.signature(func)

        # Inject additional parameters if they are in the signature.
        if 'plugin' in sig.parameters:
            params['plugin'] = self
        elif 'plugin' in params:
            del params['plugin']
        if 'request' in sig.parameters:
            params['request'] = request
        elif 'request' in params:
            del params['request']

        ba = sig.bind(**params)
        self._coerce_arguments(func, ba)
        return ba

    def _exec_func(self, func, request):
        params = request.params
        if isinstance(params, list):
            ba = self._bind_pos(func, params, request)
            return func(*ba.args, **ba.kwargs)
        elif isinstance(params, dict):
            ba = self._bind_kwargs(func, params, request)
            return func(*ba.args, **ba.kwargs)
        else:
            raise TypeError("Parameters to function call must be either a dict or a list.")

    def _dispatch_request(self, request):
        name = request.method

        if name not in self.methods:
            raise ValueError("No method {} found.".format(name))
        method = self.methods[name]
        request.background = method.background

        try:
            result = self._exec_func(method.func, request)
            if not method.background:
                # Only if this is not an async (background) call do we need to
                # return the result, otherwise the callee will eventually need
                # to call request.set_result or request.set_exception to
                # return a result or raise an exception.
                request.set_result(result)
        except Exception as e:
            request.set_exception(e)
            self.log(traceback.format_exc())

    def _dispatch_notification(self, request):
        if request.method not in self.subscriptions:
            raise ValueError("No subscription for {name} found.".format(
                name=request.method))
        func = self.subscriptions[request.method]

        try:
            self._exec_func(func, request)
        except Exception:
            self.log(traceback.format_exc())

    def _write_locked(self, obj):
        # ensure_ascii turns UTF-8 into \uXXXX so we need to suppress that,
        # then utf8 ourselves.
        s = bytes(json.dumps(obj, cls=LightningRpc.LightningJSONEncoder, ensure_ascii=False) + "\n\n", encoding='utf-8')
        with self.write_lock:
            self.stdout.buffer.write(s)
            self.stdout.flush()

    def notify(self, method, params):
        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
        }
        self._write_locked(payload)

    def log(self, message, level='info'):
        # Split the log into multiple lines and print them
        # individually. Makes tracebacks much easier to read.
        for line in message.split('\n'):
            self.notify('log', {'level': level, 'message': line})

    def _parse_request(self, jsrequest):
        request = Request(
            plugin=self,
            req_id=jsrequest.get('id', None),
            method=jsrequest['method'],
            params=jsrequest['params'],
            background=False,
        )
        return request

    def _multi_dispatch(self, msgs):
        """We received a couple of messages, now try to dispatch them all.

        Returns the last partial message that was not complete yet.
        """
        for payload in msgs[:-1]:
            # Note that we use function annotations to do Millisatoshi conversions
            # in _exec_func, so we don't use LightningJSONDecoder here.
            request = self._parse_request(json.loads(payload.decode('utf8')))

            # If this has an 'id'-field, it's a request and returns a
            # result. Otherwise it's a notification and it doesn't
            # return anything.
            if request.id is not None:
                self._dispatch_request(request)
            else:
                self._dispatch_notification(request)

        return msgs[-1]

    def run(self):
        partial = b""
        for l in self.stdin.buffer:
            partial += l

            msgs = partial.split(b'\n\n')
            if len(msgs) < 2:
                continue

            partial = self._multi_dispatch(msgs)

    def _getmanifest(self, **kwargs):
        methods = []
        hooks = []
        for method in self.methods.values():
            # Skip the builtin ones, they don't get reported
            if method.name in ['getmanifest', 'init']:
                continue

            if method.mtype == MethodType.HOOK:
                hooks.append(method.name)
                continue

            doc = inspect.getdoc(method.func)
            if not doc:
                self.log(
                    'RPC method \'{}\' does not have a docstring.'.format(method.name)
                )
                doc = "Undocumented RPC method from a plugin."
            doc = re.sub('\n+', ' ', doc)

            # Handles out-of-order use of parameters like:
            # def hello_obfus(arg1, arg2, plugin, thing3, request=None, thing5='at', thing6=21)
            argspec = inspect.getfullargspec(method.func)
            defaults = argspec.defaults
            num_defaults = len(defaults) if defaults else 0
            start_kwargs_idx = len(argspec.args) - num_defaults
            args = []
            for idx, arg in enumerate(argspec.args):
                if arg in ('plugin', 'request'):
                    continue
                # Positional arg
                if idx < start_kwargs_idx:
                    args.append("%s" % arg)
                # Keyword arg
                else:
                    args.append("[%s]" % arg)

            methods.append({
                'name': method.name,
                'category': method.category if method.category else "plugin",
                'usage': " ".join(args),
                'description': doc
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
        path = os.path.join(self.lightning_dir, self.rpc_filename)
        self.rpc = LightningRpc(path)
        for name, value in options.items():
            self.options[name]['value'] = value

        # Dispatch the plugin's init handler if any
        if self.child_init:
            return self._exec_func(self.child_init, request)
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

        if len(payload) > 0 and payload[-1] == '\n':
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
