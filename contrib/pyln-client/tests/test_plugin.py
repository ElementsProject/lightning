from pyln.client import Plugin
from pyln.client.plugin import Request, Millisatoshi, RpcException
import itertools
import pytest  # type: ignore


def test_simple_methods():
    """Test the dispatch of methods, with a variety of bindings.
    """
    call_list = []
    p = Plugin(autopatch=False)

    @p.method("test1")
    def test1(name):
        """Has a single positional argument."""
        assert name == 'World'
        call_list.append(test1)
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': {'name': 'World'}
    })
    p._dispatch_request(request)
    assert call_list == [test1]

    @p.method("test2")
    def test2(name, plugin):
        """Also asks for the plugin instance. """
        assert plugin == p
        call_list.append(test2)
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test2',
        'params': {'name': 'World'}
    })
    p._dispatch_request(request)
    assert call_list == [test1, test2]

    @p.method("test3")
    def test3(name, request):
        """Also asks for the request instance. """
        assert request is not None
        call_list.append(test3)
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test3',
        'params': {'name': 'World'}
    })
    p._dispatch_request(request)
    assert call_list == [test1, test2, test3]

    @p.method("test4")
    def test4(name):
        """Try the positional arguments."""
        assert name == 'World'
        call_list.append(test4)
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test4',
        'params': ['World']
    })
    p._dispatch_request(request)
    assert call_list == [test1, test2, test3, test4]

    @p.method("test5")
    def test5(name, request, plugin):
        """Try the positional arguments, mixing in the request and plugin."""
        assert name == 'World'
        assert request is not None
        assert p == plugin
        call_list.append(test5)
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test5',
        'params': ['World']
    })
    p._dispatch_request(request)
    assert call_list == [test1, test2, test3, test4, test5]

    answers = []

    @p.method("test6")
    def test6(name, answer=42):
        """This method has a default value for one of its params"""
        assert name == 'World'
        answers.append(answer)
        call_list.append(test6)

    # Both calls should work (with and without the default param
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test6',
        'params': ['World']
    })
    p._dispatch_request(request)
    assert call_list == [test1, test2, test3, test4, test5, test6]
    assert answers == [42]

    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test6',
        'params': ['World', 31337]
    })
    p._dispatch_request(request)
    assert call_list == [test1, test2, test3, test4, test5, test6, test6]
    assert answers == [42, 31337]


def test_methods_errors():
    """A bunch of tests that should fail calling the methods."""
    call_list = []
    p = Plugin(autopatch=False)

    # Fails because we haven't added the method yet
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': {}
    })
    with pytest.raises(ValueError):
        p._dispatch_request(request)
    assert call_list == []

    @p.method("test1")
    def test1(name):
        call_list.append(test1)

    # Attempting to add it twice should fail
    with pytest.raises(ValueError):
        p.add_method("test1", test1)

    # Fails because it is missing the 'name' argument
    request = p._parse_request({'id': 1, 'jsonrpc': '2.0', 'method': 'test1', 'params': {}})
    with pytest.raises(TypeError):
        p._exec_func(test1, request)
    assert call_list == []

    # The same with positional arguments
    request = p._parse_request({'id': 1, 'jsonrpc': '2.0', 'method': 'test1', 'params': []})
    with pytest.raises(TypeError):
        p._exec_func(test1, request)
    assert call_list == []

    # Fails because we have a non-matching argument
    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': {'name': 'World', 'extra': 1}
    })
    with pytest.raises(TypeError):
        p._exec_func(test1, request)
    assert call_list == []

    request = p._parse_request({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': ['World', 1]
    })

    with pytest.raises(TypeError):
        p._exec_func(test1, request)
    assert call_list == []


def test_method_exceptions():
    """A bunch of tests that should fail calling the methods."""
    p = Plugin(autopatch=False)

    def fake_write_result(resultdict):
        global result_dict
        result_dict = resultdict

    @p.method("test_raise")
    def test_raise():
        raise RpcException("testing RpcException", code=-1000)

    req = Request(p, 1, "test_raise", {})
    req._write_result = fake_write_result
    p._dispatch_request(req)
    assert result_dict['jsonrpc'] == '2.0'
    assert result_dict['id'] == 1
    assert result_dict['error']['code'] == -1000
    assert result_dict['error']['message'] == "testing RpcException"

    @p.method("test_raise2")
    def test_raise2():
        raise Exception("normal exception")

    req = Request(p, 1, "test_raise2", {})
    req._write_result = fake_write_result
    p._dispatch_request(req)
    assert result_dict['jsonrpc'] == '2.0'
    assert result_dict['id'] == 1
    assert result_dict['error']['code'] == -32600
    assert result_dict['error']['message'] == "Error while processing test_raise2: normal exception"


def test_positional_inject():
    p = Plugin()
    rdict = Request(
        plugin=p,
        req_id=1,
        method='func',
        params={'a': 1, 'b': 2, 'kwa': 3, 'kwb': 4}
    )
    rarr = Request(
        plugin=p,
        req_id=1,
        method='func',
        params=[1, 2, 3, 4],
    )

    def pre_args(plugin, a, b, kwa=3, kwb=4):
        assert (plugin, a, b, kwa, kwb) == (p, 1, 2, 3, 4)

    def in_args(a, plugin, b, kwa=3, kwb=4):
        assert (plugin, a, b, kwa, kwb) == (p, 1, 2, 3, 4)

    def post_args(a, b, plugin, kwa=3, kwb=4):
        assert (plugin, a, b, kwa, kwb) == (p, 1, 2, 3, 4)

    def post_kwargs(a, b, kwa=3, kwb=4, plugin=None):
        assert (plugin, a, b, kwa, kwb) == (p, 1, 2, 3, 4)

    def in_multi_args(a, request, plugin, b, kwa=3, kwb=4):
        assert request in [rarr, rdict]
        assert (plugin, a, b, kwa, kwb) == (p, 1, 2, 3, 4)

    def in_multi_mix_args(a, plugin, b, request=None, kwa=3, kwb=4):
        assert request in [rarr, rdict]
        assert (plugin, a, b, kwa, kwb) == (p, 1, 2, 3, 4)

    def extra_def_arg(a, b, c, d, e=42):
        """ Also uses a different name for kwa and kwb
        """
        assert (a, b, c, d, e) == (1, 2, 3, 4, 42)

    def count(plugin, count, request):
        assert count == 42 and plugin == p

    funcs = [pre_args, in_args, post_args, post_kwargs, in_multi_args]

    for func, request in itertools.product(funcs, [rdict, rarr]):
        p._exec_func(func, request)

    p._exec_func(extra_def_arg, rarr)

    p._exec_func(count, Request(
        plugin=p,
        req_id=1,
        method='func',
        params=[42],
    ))

    # This should fail since it is missing one positional argument
    with pytest.raises(TypeError):
        p._exec_func(count, Request(
            plugin=p,
            req_id=1,
            method='func',
            params=[])
        )


def test_bind_pos():
    p = Plugin(autopatch=False)

    req = object()
    params = ['World']

    def test1(name):
        assert name == 'World'
    bound = p._bind_pos(test1, params, req)
    test1(*bound.args, **bound.kwargs)

    def test2(name, plugin):
        assert name == 'World'
        assert plugin == p
    bound = p._bind_pos(test2, params, req)
    test2(*bound.args, **bound.kwargs)

    def test3(plugin, name):
        assert name == 'World'
        assert plugin == p
    bound = p._bind_pos(test3, params, req)
    test3(*bound.args, **bound.kwargs)

    def test4(plugin, name, request):
        assert name == 'World'
        assert plugin == p
        assert request == req
    bound = p._bind_pos(test4, params, req)
    test4(*bound.args, **bound.kwargs)

    def test5(request, name, plugin):
        assert name == 'World'
        assert plugin == p
        assert request == req
    bound = p._bind_pos(test5, params, req)
    test5(*bound.args, **bound.kwargs)

    def test6(request, name, plugin, answer=42):
        assert name == 'World'
        assert plugin == p
        assert request == req
        assert answer == 42
    bound = p._bind_pos(test6, params, req)
    test6(*bound.args, **bound.kwargs)

    # Now mix in a catch-all parameter that needs to be assigned
    def test6(request, name, plugin, *args, **kwargs):
        assert name == 'World'
        assert plugin == p
        assert request == req
        assert args == (42,)
        assert kwargs == {}
    bound = p._bind_pos(test6, params + [42], req)
    test6(*bound.args, **bound.kwargs)


def test_bind_kwargs():
    p = Plugin(autopatch=False)

    req = object()
    params = {'name': 'World'}

    def test1(name):
        assert name == 'World'
    bound = p._bind_kwargs(test1, params, req)
    test1(*bound.args, **bound.kwargs)

    def test2(name, plugin):
        assert name == 'World'
        assert plugin == p
    bound = p._bind_kwargs(test2, params, req)
    test2(*bound.args, **bound.kwargs)

    def test3(plugin, name):
        assert name == 'World'
        assert plugin == p
    bound = p._bind_kwargs(test3, params, req)
    test3(*bound.args, **bound.kwargs)

    def test4(plugin, name, request):
        assert name == 'World'
        assert plugin == p
        assert request == req
    bound = p._bind_kwargs(test4, params, req)
    test4(*bound.args, **bound.kwargs)

    def test5(request, name, plugin):
        assert name == 'World'
        assert plugin == p
        assert request == req
    bound = p._bind_kwargs(test5, params, req)
    test5(*bound.args, **bound.kwargs)

    def test6(request, name, plugin, answer=42):
        assert name == 'World'
        assert plugin == p
        assert request == req
        assert answer == 42
    bound = p._bind_kwargs(test6, params, req)
    test6(*bound.args, **bound.kwargs)

    # Now mix in a catch-all parameter that needs to be assigned
    def test6(request, name, plugin, *args, **kwargs):
        assert name == 'World'
        assert plugin == p
        assert request == req
        assert args == ()
        assert kwargs == {'answer': 42}
    bound = p._bind_kwargs(test6, {'name': 'World', 'answer': 42}, req)
    test6(*bound.args, **bound.kwargs)


def test_argument_coercion():
    p = Plugin(autopatch=False)

    def test1(msat: Millisatoshi):
        assert isinstance(msat, Millisatoshi)

    ba = p._bind_kwargs(test1, {"msat": "100msat"}, None)
    test1(*ba.args)

    ba = p._bind_pos(test1, ["100msat"], None)
    test1(*ba.args, **ba.kwargs)


def test_duplicate_result():
    p = Plugin(autopatch=False)

    def test1(request):
        request.set_result(1)     # MARKER1
        request.set_result(1)

    req = Request(p, req_id=1, method="test1", params=[])
    ba = p._bind_kwargs(test1, {}, req)
    with pytest.raises(ValueError, match=r'current state is RequestState\.FINISHED(.*\n.*)*MARKER1'):
        test1(*ba.args)

    def test2(request):
        request.set_exception(1)  # MARKER2
        request.set_exception(1)

    req = Request(p, req_id=2, method="test2", params=[])
    ba = p._bind_kwargs(test2, {}, req)
    with pytest.raises(ValueError, match=r'current state is RequestState\.FAILED(.*\n*.*)*MARKER2'):
        test2(*ba.args)

    def test3(request):
        request.set_exception(1)  # MARKER3
        request.set_result(1)

    req = Request(p, req_id=3, method="test3", params=[])
    ba = p._bind_kwargs(test3, {}, req)
    with pytest.raises(ValueError, match=r'current state is RequestState\.FAILED(.*\n*.*)*MARKER3'):
        test3(*ba.args)

    def test4(request):
        request.set_result(1)     # MARKER4
        request.set_exception(1)

    req = Request(p, req_id=4, method="test4", params=[])
    ba = p._bind_kwargs(test4, {}, req)
    with pytest.raises(ValueError, match=r'current state is RequestState\.FINISHED(.*\n*.*)*MARKER4'):
        test4(*ba.args)


def test_usage():
    p = Plugin(autopatch=False)

    @p.method("some_method")
    def some_method(some_arg: str = None):
        """some description"""
        pass

    manifest = p._getmanifest()
    usage = p.get_usage()

    assert manifest['rpcmethods'][0]['name'] == 'some_method'
    assert "some_arg" in manifest['rpcmethods'][0]['usage']
    assert "some description" in manifest['rpcmethods'][0]['usage']
    assert "some_method" in usage
    assert "some_arg" in usage
    assert "some description" in usage
