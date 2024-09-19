import inspect
import io
import json
import logging
import math
import os
import re
import sys
import traceback
from binascii import hexlify
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .lightning import LightningRpc, Millisatoshi

# Notice that this definition is incomplete as it only checks the
# top-level. Arrays and Dicts could contain types that aren't encodeable. This
# limitation stems from the fact that recursive types are not really supported
# yet.
JSONType = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]

# Yes, decorators are weird...
NoneDecoratorType = Callable[..., Callable[..., None]]
JsonDecoratorType = Callable[..., Callable[..., JSONType]]


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
    def __init__(self, name: str, func: Callable[..., JSONType],
                 mtype: MethodType = MethodType.RPCMETHOD,
                 deprecated: Union[bool, List[str]] = None,
                 description: str = None):
        self.name = name
        self.func = func
        self.mtype = mtype
        self.background = False
        self.deprecated = deprecated
        self.description = description
        self.before: List[str] = []
        self.after: List[str] = []

    def get_usage(self):
        # Handles out-of-order use of parameters like:
        #
        # ```python3
        #
        # def hello_obfus(arg1, arg2, plugin, thing3, request=None,
        #                 thing5='at', thing6=21)
        #
        # ```
        argspec = inspect.getfullargspec(self.func)
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

        if self.description is not None:
            args.append("\n%s" % self.description)

        return " ".join(args)


class RpcException(Exception):
    # -32600 == "Invalid Request"
    def __init__(self, message: str, code: int = -32600):
        self.code = code
        self.message = message
        super().__init__("RpcException: {}".format(message))


class Request(dict):
    """A request object that wraps params and allows async return
    """
    def __init__(self, plugin: 'Plugin', req_id: Optional[str], method: str,
                 params: Any, background: bool = False):
        self.method = method
        self.params = params
        self.background = background
        self.plugin = plugin
        self.state = RequestState.PENDING
        self.id = req_id
        self.termination_tb: Optional[str] = None

    def getattr(self, key: str) -> Union[Method, Any, int]:
        if key == "params":
            return self.params
        elif key == "id":
            return self.id
        elif key == "method":
            return self.method
        else:
            raise ValueError(
                'Cannot get attribute "{key}" on Request'.format(key=key)
            )

    def set_result(self, result: Any) -> None:
        if self.state != RequestState.PENDING:
            assert self.termination_tb is not None
            raise ValueError(
                "Cannot set the result of a request that is not pending, "
                "current state is {state}. Request previously terminated at\n"
                "{tb}".format(state=self.state, tb=self.termination_tb))
        self.result = result
        self._write_result({
            'jsonrpc': '2.0',
            'id': self.id,
            'result': self.result
        })
        self.state = RequestState.FINISHED
        self.termination_tb = "".join(traceback.extract_stack().format()[:-1])

    def set_exception(self, exc: Union[Exception, RpcException]) -> None:
        if self.state != RequestState.PENDING:
            assert self.termination_tb is not None
            raise ValueError(
                "Cannot set the exception of a request that is not pending, "
                "current state is {state}. Request previously terminated at\n"
                "{tb}".format(state=self.state, tb=self.termination_tb))
        self.exc = exc
        if isinstance(exc, RpcException):
            code = exc.code
            message = exc.message
        else:
            code = -32600  # "Invalid Request"
            message = ("Error while processing {method}: {exc}"
                       .format(method=self.method, exc=str(exc)))
        self._write_result({
            'jsonrpc': '2.0',
            'id': self.id,
            "error": {
                "code": code,
                "message": message,
                # 'data' field "may be omitted."
                "traceback": traceback.format_exc(),
            },
        })
        self.state = RequestState.FAILED
        self.termination_tb = "".join(traceback.extract_stack().format()[:-1])

    def _write_result(self, result: dict) -> None:
        self.plugin._write_locked(result)

    def _notify(self, method: str, params: JSONType) -> None:
        """Send a notification to the caller.

        Can contain a variety of things, but is usually used to report
        progress or command status.

        """
        self._write_result({
            'jsonrpc': '2.0',
            'params': params,
            "method": method,
        })

    def notify(self, message: str, level: str = 'info') -> None:
        """Send a message notification to the caller.
        """
        self._notify(
            "message",
            params={
                'id': self.id,
                'level': level,
                'message': message,
            }
        )

    def progress(self,
                 progress: int,
                 total: int,
                 stage: Optional[int] = None,
                 stage_total: Optional[int] = None
                 ) -> None:
        d: Dict[str, JSONType] = {
            "id": self.id,
            "num": progress,
            "total": total,
        }
        if stage is not None and stage_total is not None:
            d['stage'] = {"num": stage, "total": stage_total}

        self._notify("progress", d)


@dataclass
class Option:
    name: str
    default: Optional[Any]
    description: Optional[str]
    opt_type: str
    value: Optional[Any]
    multi: bool
    deprecated: Optional[Union[bool, List[str]]]
    dynamic: bool
    on_change: Optional[Callable[["Plugin", str, Optional[Any]], None]]

    def __getitem__(self, key):
        """Backwards compatibility for callers who directly asked for ['value']"""
        if key == 'value':
            return self.value
        raise KeyError(f"Key {key} not supported, only 'value' is")

    def json(self) -> Dict[str, Any]:
        ret = {
            'name': self.name,
            'description': self.description,
            'type': self.opt_type,
            'multi': self.multi,
            'deprecated': self.deprecated,
            'dynamic': self.dynamic,
        }
        if self.default is not None:
            ret['default'] = self.default
        return ret


# If a hook call fails we need to coerce it into something the main daemon can
# handle. Returning an error is not an option since we explicitly do not allow
# those as a response to the calls, otherwise the only option we have is to
# crash the main daemon. The goal of these is to present a safe fallback
# should the hook call fail unexpectedly.
hook_fallbacks = {
    'htlc_accepted': {
        'result': 'fail',
        'failure_message': '2002'  # Fail with a temporary node failure
    },
    'peer_connected': {'result': 'continue'},
    # commitment_revocation cannot recover from failing, let lightningd crash
    # db_write cannot recover from failing, let lightningd crash
    'invoice_payment': {'result': 'continue'},
    'openchannel': {'result': 'reject'},
    'rpc_command': {'result': 'continue'},
    'custommsg': {'result': 'continue'},
}


class Plugin(object):
    """Controls interactions with lightningd, and bundles functionality.

    The Plugin class serves two purposes: it collects RPC methods and
    options, and offers a control loop that dispatches incoming RPC
    calls and hooks.

    """

    def __init__(self, stdout: Optional[io.TextIOBase] = None,
                 stdin: Optional[io.TextIOBase] = None, autopatch: bool = True,
                 dynamic: bool = True,
                 init_features: Optional[Union[int, str, bytes]] = None,
                 node_features: Optional[Union[int, str, bytes]] = None,
                 invoice_features: Optional[Union[int, str, bytes]] = None,
                 custom_msgs: Optional[List[int]] = None):
        self.methods = {
            'init': Method('init', self._init, MethodType.RPCMETHOD),
            'setconfig': Method('setconfig', self._set_config, MethodType.RPCMETHOD)
        }

        self.options: Dict[str, Option] = {}
        self.notification_topics: List[str] = []
        self.custom_msgs = custom_msgs

        def convert_featurebits(
                bits: Optional[Union[int, str, bytes]]) -> Optional[str]:
            """Convert the featurebits into the bytes required to hexencode.
            """
            if bits is None:
                return None

            elif isinstance(bits, int):
                bitlen = math.ceil(math.log(bits, 256))
                return hexlify(bits.to_bytes(bitlen, 'big')).decode('ASCII')

            elif isinstance(bits, str):
                # Assume this is already hex encoded
                return bits

            elif isinstance(bits, bytes):
                return hexlify(bits).decode('ASCII')

            else:
                raise ValueError(
                    "Could not convert featurebits to hex-encoded string"
                )

        self.featurebits = {
            'init': convert_featurebits(init_features),
            'node': convert_featurebits(node_features),
            'invoice': convert_featurebits(invoice_features),
        }

        # A dict from topics to handler functions
        self.subscriptions: Dict[str, Callable[..., None]] = {}

        if not stdout:
            self.stdout = sys.stdout
        if not stdin:
            self.stdin = sys.stdin

        self.lightning_version = None
        if os.getenv('LIGHTNINGD_VERSION'):
            self.lightning_version = os.getenv('LIGHTNINGD_VERSION')
        if os.getenv('LIGHTNINGD_PLUGIN') and autopatch:
            monkey_patch(self, stdout=True, stderr=True)

        self.add_method("getmanifest", self._getmanifest, background=False)
        self.rpc_filename: Optional[str] = None
        self.lightning_dir: Optional[str] = None
        self.rpc: Optional[LightningRpc] = None
        self.startup = True
        self.dynamic = dynamic

        # The function registering as init may return a dict of the
        # form `{'disable': 'why'}` to self-disable, however most
        # commonly you'll want to return `None`
        self.child_init: Optional[Callable[..., Optional[dict]]] = None

        self.write_lock = RLock()

        # Initialize the logging system with a handler that passes the logs to
        # lightning for display.
        log_handler = PluginLogHandler(self)
        formatter = logging.Formatter('%(name)-12s: %(message)s')
        log_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(log_handler)

    def add_method(self, name: str, func: Callable[..., Any],
                   background: bool = False,
                   deprecated: Optional[Union[bool, List[str]]] = None,
                   description: str = None) -> None:
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

        `deprecated` True means that it won't appear unless `allow-deprecated-apis`
        is true (the default), or if list of version string (e.g. "v23.08"), then
        start deprecation cycle at that version (and removal after second entry in list).
        """
        if name in self.methods:
            raise ValueError(
                "Name {} is already bound to a method.".format(name)
            )

        # Register the function with the name
        method = Method(name, func, MethodType.RPCMETHOD, deprecated, description)
        method.background = background
        self.methods[name] = method

    def add_subscription(self, topic: str, func: Callable[..., None]) -> None:
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

        # Make sure the notification callback has a **kwargs argument so that
        # it doesn't break if we add more arguments to the call later
        # on. Issue a warning if it does not.
        s = inspect.signature(func)
        kinds = [p.kind for p in s.parameters.values()]
        if inspect.Parameter.VAR_KEYWORD not in kinds:
            self.log(
                "Notification handler {} for notification {} does not have a "
                "variable keyword argument. It is strongly suggested to add "
                "`**kwargs` as last parameter to hook and notification "
                "handlers.".format(func.__name__, topic), level="warn")

        self.subscriptions[topic] = func

    def subscribe(self, topic: str) -> NoneDecoratorType:
        """Function decorator to register a notification handler.

        """
        # Yes, decorator type annotations are just weird, don't think too much
        # about it...
        def decorator(f: Callable[..., None]) -> Callable[..., None]:
            self.add_subscription(topic, f)
            return f
        return decorator

    def add_option(self, name: str, default: Optional[Any],
                   description: Optional[str],
                   opt_type: str = "string",
                   deprecated: Optional[Union[bool, List[str]]] = None,
                   multi: bool = False,
                   dynamic=False,
                   on_change: Optional[Callable[["Plugin", str, Optional[Any]], None]] = None,
                   ) -> None:
        """Add an option that we'd like to register with lightningd.

        Needs to be called before `Plugin.run`, otherwise we might not
        end up getting it set.

        """
        if name in self.options:
            raise ValueError(
                "Name {} is already used by another option".format(name)
            )

        if opt_type not in ["string", "int", "bool", "flag"]:
            raise ValueError(
                '{} not in supported type set (string, int, bool, flag)'.format(opt_type)
            )

        if on_change is not None and not dynamic:
            raise ValueError(
                'Option {} has on_change callback but is not dynamic'.format(name)
            )

        self.options[name] = Option(
            name=name,
            default=default,
            description=description,
            opt_type=opt_type,
            value=None,
            dynamic=dynamic,
            on_change=on_change,
            multi=multi,
            deprecated=deprecated if deprecated is not None else False,
        )

    def add_flag_option(self, name: str, description: str,
                        deprecated: Optional[Union[bool, List[str]]] = None,
                        dynamic: bool = False) -> None:
        """Add a flag option that we'd like to register with lightningd.

        Needs to be called before `Plugin.run`, otherwise we might not
        end up getting it set.

        """
        self.add_option(name, None, description, opt_type="flag",
                        deprecated=deprecated, dynamic=dynamic)

    def add_notification_topic(self, topic: str):
        """Announce that the plugin will emit notifications for the topic.
        """
        self.notification_topics.append(topic)

    def get_option(self, name: str) -> Optional[Any]:
        if name not in self.options:
            raise ValueError("No option with name {} registered".format(name))

        if self.options[name].value is not None:
            return self.options[name].value
        else:
            return self.options[name].default

    def async_method(self, method_name: str, category: Optional[str] = None,
                     desc: Optional[str] = None,
                     long_desc: Optional[str] = None,
                     deprecated: Optional[Union[bool, List[str]]] = None) -> NoneDecoratorType:
        """Decorator to add an async plugin method to the dispatch table.

        Internally uses add_method.
        """
        def decorator(f: Callable[..., None]) -> Callable[..., None]:
            for attr, attr_name in [(category, "Category"), (desc, "Description"), (long_desc, "Long description")]:
                if attr is not None:
                    self.log("{} is deprecated but defined in method {}; it will be ignored by Core Lightning".format(attr_name, method_name), level="warn")
            self.add_method(method_name, f, background=True, deprecated=deprecated)
            return f
        return decorator

    def method(self, method_name: str, category: Optional[str] = None,
               desc: Optional[str] = None,
               long_desc: Optional[str] = None,
               deprecated: Union[bool, List[str]] = None,
               description: str = None) -> JsonDecoratorType:
        """Decorator to add a plugin method to the dispatch table.

        Internally uses add_method.
        """
        def decorator(f: Callable[..., JSONType]) -> Callable[..., JSONType]:
            for attr, attr_name in [(category, "Category"), (desc, "Description"), (long_desc, "Long description")]:
                if attr is not None:
                    self.log("{} is deprecated but defined in method {}; it will be ignored by Core Lightning".format(attr_name, method_name), level="warn")
            self.add_method(method_name, f, background=False, deprecated=deprecated, description=f.__doc__)
            return f
        return decorator

    def add_hook(self, name: str, func: Callable[..., JSONType],
                 background: bool = False,
                 before: Optional[List[str]] = None,
                 after: Optional[List[str]] = None) -> None:
        """Register a hook that is called synchronously by lightningd on events
        """
        if name in self.methods:
            raise ValueError(
                "Method {name} was already registered".format(name=name)
            )

        # Make sure the hook callback has a **kwargs argument so that it
        # doesn't break if we add more arguments to the call later on. Issue a
        # warning if it does not.
        s = inspect.signature(func)
        kinds = [p.kind for p in s.parameters.values()]
        if inspect.Parameter.VAR_KEYWORD not in kinds:
            self.log(
                "Hook handler {} for hook {} does not have a variable keyword "
                "argument. It is strongly suggested to add `**kwargs` as last "
                "parameter to hook and notification handlers.".format(
                    func.__name__, name), level="warn")

        method = Method(name, func, MethodType.HOOK)
        method.background = background
        method.before = []
        if before:
            method.before = before
        method.after = []
        if after:
            method.after = after
        self.methods[name] = method

    def hook(self, method_name: str,
             before: List[str] = None,
             after: List[str] = None) -> JsonDecoratorType:
        """Decorator to add a plugin hook to the dispatch table.

        Internally uses add_hook.
        """
        def decorator(f: Callable[..., JSONType]) -> Callable[..., JSONType]:
            self.add_hook(method_name, f, background=False, before=before, after=after)
            return f
        return decorator

    def async_hook(self, method_name: str) -> NoneDecoratorType:
        """Decorator to add an async plugin hook to the dispatch table.

        Internally uses add_hook.
        """
        def decorator(f: Callable[..., None]) -> Callable[..., None]:
            self.add_hook(method_name, f, background=True)
            return f
        return decorator

    def init(self) -> NoneDecoratorType:
        """Decorator to add a function called after plugin initialization
        """
        def decorator(f: Callable[..., None]) -> Callable[..., None]:
            if self.child_init is not None:
                raise ValueError(
                    'The @plugin.init decorator should only be used once'
                )
            self.child_init = f
            return f
        return decorator

    @staticmethod
    def _coerce_arguments(
            func: Callable[..., Any],
            ba: inspect.BoundArguments) -> inspect.BoundArguments:
        args = OrderedDict()
        annotations = {}
        if hasattr(func, "__annotations__"):
            annotations = func.__annotations__

        for key, val in ba.arguments.items():
            annotation = annotations.get(key, None)
            if annotation is not None and annotation == Millisatoshi:
                args[key] = Millisatoshi(val)
            else:
                args[key] = val
        ba.arguments = args
        return ba

    def _bind_pos(self, func: Callable[..., Any], params: List[str],
                  request: Request) -> inspect.BoundArguments:
        """Positional binding of parameters
        """
        assert isinstance(params, list)
        sig = inspect.signature(func)

        # Collect injections so we can sort them and insert them in the right
        # order later. If we don't apply inject them in increasing order we
        # might shift away an earlier injection.
        injections: List[Tuple[int, Any]] = []
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

    def _bind_kwargs(self, func: Callable[..., Any], params: Dict[str, Any],
                     request: Request) -> inspect.BoundArguments:
        """Keyword based binding of parameters
        """
        assert isinstance(params, dict)
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

    def _exec_func(self, func: Callable[..., Any],
                   request: Request) -> JSONType:
        # By default, any RPC calls this makes will have JSON id prefixed by incoming id.
        if self.rpc:
            self.rpc.cmdprefix = request.id
        params = request.params
        if isinstance(params, list):
            ba = self._bind_pos(func, params, request)
            ret = func(*ba.args, **ba.kwargs)
        elif isinstance(params, dict):
            ba = self._bind_kwargs(func, params, request)
            ret = func(*ba.args, **ba.kwargs)
        else:
            if self.rpc:
                self.rpc.cmdprefix = None
            raise TypeError(
                "Parameters to function call must be either a dict or a list."
            )
        if self.rpc:
            self.rpc.cmdprefix = None
        return ret

    def _dispatch_request(self, request: Request) -> None:
        name = request.method

        if name not in self.methods:
            raise ValueError("No method {} found.".format(name))
        method = self.methods[name]
        request.background = method.background

        try:
            result = self._exec_func(method.func, request)
            if not method.background:
                # Only if this is a synchronous (background=False) call do we need to
                # return the result. Otherwise the callee (method) will eventually need
                # to call request.set_result or request.set_exception to
                # return a result or raise an exception.
                request.set_result(result)
        except Exception as e:
            if name in hook_fallbacks:
                response = hook_fallbacks[name]
                self.log((
                    "Hook handler for {name} failed with an exception. "
                    "Returning safe fallback response {response} to avoid "
                    "crashing the main daemon. Please contact the plugin "
                    "author!"
                ).format(name=name, response=response), level="error")

                request.set_result(response)
            else:
                request.set_exception(e)
            self.log(traceback.format_exc())

    def _dispatch_notification(self, request: Request) -> None:
        if request.method in self.subscriptions:
            func = self.subscriptions[request.method]
        # Wildcard 'all' subscriptions using asterisk
        elif '*' in self.subscriptions:
            func = self.subscriptions['*']
        else:
            raise ValueError(f"No subscription for {request.method} found.")

        try:
            self._exec_func(func, request)
        except Exception:
            self.log(traceback.format_exc())

    def _write_locked(self, obj: JSONType) -> None:
        # ensure_ascii turns UTF-8 into \uXXXX so we need to suppress that,
        # then utf8 ourselves.
        s = bytes(json.dumps(
            obj,
            ensure_ascii=False
        ) + "\n\n", encoding='utf-8')
        with self.write_lock:
            self.stdout.buffer.write(s)
            self.stdout.flush()

    def notify(self, method: str, params: JSONType) -> None:
        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
        }
        self._write_locked(payload)

    def log(self, message: str, level: str = 'info') -> None:
        # Split the log into multiple lines and print them
        # individually. Makes tracebacks much easier to read.
        for line in message.split('\n'):
            self.notify('log', {'level': level, 'message': line})

    def notify_message(self, request: Request, message: str,
                       level: str = 'info') -> None:
        """Send a notification message to sender of this request"""
        request.notify(message=message, level=level)

    def notify_progress(self, request: Request,
                        progress: int, progress_total: int,
                        stage: Optional[int] = None,
                        stage_total: Optional[int] = None) -> None:
        """Send a progress message to sender of this request: if more than one stage, set stage and stage_total"""
        request.progress(progress, progress_total, stage, stage_total)

    def _parse_request(self, jsrequest: Dict[str, JSONType]) -> Request:
        request = Request(
            plugin=self,
            req_id=jsrequest.get('id', None),
            method=str(jsrequest['method']),
            params=jsrequest['params'],
            background=False,
        )
        return request

    def _multi_dispatch(self, msgs: List[bytes]) -> bytes:
        """We received a couple of messages, now try to dispatch them all.

        Returns the last partial message that was not complete yet.
        """
        for payload in msgs[:-1]:
            # Note that we use function annotations to do Millisatoshi
            # conversions in _exec_func, so we don't use LightningJSONDecoder
            # here.
            request = self._parse_request(json.loads(payload.decode('utf8')))

            # If this has an 'id'-field, it's a request and returns a
            # result. Otherwise it's a notification and it doesn't
            # return anything.
            if request.id is not None:
                self._dispatch_request(request)
            else:
                self._dispatch_notification(request)

        return msgs[-1]

    def get_usage(self):
        import textwrap

        executable = os.path.abspath(sys.argv[0])
        overview = textwrap.dedent("""
        Hi, it looks like you're trying to run a plugin from the
        command line. Plugins are usually started and controlled by
        lightningd, which allows you to simply specify which plugins
        you'd like to run using the --plugin command line option when
        starting lightningd. The following is an example of how that'd
        look:

          $ lightningd --plugin={executable}

        If lightningd is already running, you can also start a plugin
        by using the cli:

          $ lightning-cli plugin start /path/to/a/plugin

        Since we're here however let me tell you about this plugin.
        """).format(executable=executable)

        methods_header = textwrap.dedent("""

        RPC methods
        ===========

        Plugins may provide additional RPC methods that you can simply
        call as if they were built-in methods from lightningd
        itself. To call them just use lightning-cli or any other
        frontend. The following methods are defined by this plugin:
        """)

        parts = [overview]

        method_tpl = textwrap.dedent("""
          {name}
        """)

        for method in self.methods.values():
            if method.name in ['init', 'getmanifest', 'setconfig']:
                # Skip internal methods provided by all plugins
                continue

            if method.mtype != MethodType.RPCMETHOD:
                # Don't include non-rpc-methods in the rpc-method
                # section
                continue

            if methods_header is not None:
                # Listen carefully, I shall say this only once :-)
                parts.append(methods_header)
                methods_header = None

            parts.append(method_tpl.format(
                name="%s %s" % (method.name, method.get_usage()),
            ))

        options_header = textwrap.dedent("""
        Command line options
        ====================

        This plugin exposes the following command line options. They
        can be specified just like any other you might gice lightning
        at startup. The following options are exposed by this plugin:
        """)

        option_tpl = textwrap.dedent("""
          --{name}={typ}  (default: {default}
        {doc}
        """)
        for opt in self.options.values():
            if options_header is not None:
                parts.append(options_header)
                options_header = None

            if opt.description:
                doc = textwrap.indent(opt.description, prefix="    ")
            else:
                doc = ""

            if opt.multi:
                doc += "\n\n    This option can be specified multiple times"

            parts.append(option_tpl.format(
                name=opt.name,
                doc=doc,
                default=opt.default,
                typ=opt.opt_type,
            ))
        return "".join(parts)

    def print_usage(self):
        sys.stdout.write(self.get_usage())
        sys.stdout.write("\n")

    def run(self) -> None:
        # If we are not running inside lightningd we'll print usage
        # and some information about the plugin.
        if os.environ.get('LIGHTNINGD_PLUGIN', None) != '1':
            return self.print_usage()

        partial = b""
        for l in self.stdin.buffer:
            partial += l

            msgs = partial.split(b'\n\n')
            if len(msgs) < 2:
                continue

            partial = self._multi_dispatch(msgs)

    def _getmanifest(self, **kwargs) -> JSONType:
        if 'allow-deprecated-apis' in kwargs:
            self.deprecated_apis = kwargs['allow-deprecated-apis']
        else:
            # 0.9.0 and before didn't offer this, so assume "yes".
            self.deprecated_apis = True

        methods = []
        hooks = []
        for method in self.methods.values():
            # Skip the builtin ones, they don't get reported
            if method.name in ['getmanifest', 'init', 'setconfig']:
                continue

            if method.mtype == MethodType.HOOK:
                hooks.append({'name': method.name,
                              'before': method.before,
                              'after': method.after})
                continue

            doc = inspect.getdoc(method.func)
            if not doc:
                self.log(
                    'RPC method \'{}\' does not have a docstring.'.format(
                        method.name
                    )
                )
                doc = "Undocumented RPC method from a plugin."
            doc = re.sub('\n+', ' ', doc)

            methods.append({
                'name': method.name,
                'usage': method.get_usage()
            })

        manifest = {
            'options': list(d.json() for d in self.options.values()),
            'rpcmethods': methods,
            'subscriptions': list(self.subscriptions.keys()),
            'hooks': hooks,
            'dynamic': self.dynamic,
            'nonnumericids': True,
            'notifications': [
                {"method": name} for name in self.notification_topics
            ],
        }

        # Compact the features a bit, not important.
        features = {k: v for k, v in self.featurebits.items() if v is not None}
        if features is not None:
            manifest['featurebits'] = features

        if self.custom_msgs is not None:
            manifest['custommessages'] = self.custom_msgs

        return manifest

    def _init(self, options: Dict[str, JSONType],
              configuration: Dict[str, JSONType],
              request: Request) -> JSONType:

        def verify_str(d: Dict[str, JSONType], key: str) -> str:
            v = d.get(key)
            if not isinstance(v, str):
                raise TypeError("Wrong argument to init: expected {key} to be"
                                " a string, got {v}".format(key=key, v=v))
            return v

        def verify_bool(d: Dict[str, JSONType], key: str) -> bool:
            v = d.get(key)
            if not isinstance(v, bool):
                raise TypeError("Wrong argument to init: expected {key} to be"
                                " a bool, got {v}".format(key=key, v=v))
            return v

        self.rpc_filename = verify_str(configuration, 'rpc-file')
        self.lightning_dir = verify_str(configuration, 'lightning-dir')

        path = os.path.join(self.lightning_dir, self.rpc_filename)
        self.rpc = LightningRpc(path)
        self.startup = verify_bool(configuration, 'startup')
        for name, value in options.items():
            self.options[name].value = value

        # Dispatch the plugin's init handler if any
        if self.child_init:
            return self._exec_func(self.child_init, request)
        return None

    def _set_config(self, config: str, val: Optional[Any]) -> None:
        """Called when the value of a dynamic option is changed
        """
        opt = self.options[config]
        cb = opt.on_change
        if cb is not None:
            # This may throw an exception: caller will turn into error msg for user.
            cb(self, config, val)

        opt.value = val


class PluginStream(object):
    """Sink that turns everything that is written to it into a notification.
    """

    def __init__(self, plugin: Plugin, level: str = "info"):
        self.plugin = plugin
        self.level = level
        self.buff = ''

    def write(self, payload: str) -> None:
        self.buff += payload

        if len(payload) > 0 and payload[-1] == '\n':
            self.flush()

    def flush(self) -> None:
        lines = self.buff.split('\n')
        if len(lines) < 2:
            return

        for l in lines[:-1]:
            self.plugin.log(l, self.level)

        # lines[-1] is either an empty string or a partial line
        self.buff = lines[-1]


def monkey_patch(plugin: Plugin, stdout: bool = True,
                 stderr: bool = False) -> None:
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


class PluginLogHandler(logging.StreamHandler):
    def __init__(self, plugin: Plugin) -> None:
        logging.StreamHandler.__init__(self, stream=None)
        self.plugin = plugin

        # Map the numeric levels to the string levels lightningd understands.
        self.levels = {
            logging.CRITICAL: 'error',
            logging.ERROR: 'error',
            logging.WARNING: 'info',
            logging.INFO: 'info',
            logging.DEBUG: 'debug',
            logging.NOTSET: 'debug',
        }

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a record.

        If a formatter is specified, it is used to format the record. Numeric
        levels are translated into strings that lightningd understands. If
        exception information is present, it is formatted using
        traceback.print_exception and appended to the stream.

        """
        try:
            msg = self.format(record)
            level = self.levels.get(record.levelno, 'info')
            self.plugin.log(msg, level=level)
        except RecursionError:  # See issue https://bugs.python.org/issue36272
            raise
        except Exception:
            self.handleError(record)  # Writes errors in logging system to stderr
        pass

    def flush(self) -> None:
        """Flushing is a no-op since each message is written as it comes in.
        """
        pass
