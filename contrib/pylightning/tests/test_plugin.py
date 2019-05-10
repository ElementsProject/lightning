from lightning import Plugin
from lightning.plugin import Request, Millisatoshi
import itertools
import pytest


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
