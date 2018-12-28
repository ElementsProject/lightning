from lightning import Plugin


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
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': {'name': 'World'}
    }
    p._dispatch(request)
    assert call_list == [test1]

    @p.method("test2")
    def test2(name, plugin):
        """Also asks for the plugin instance. """
        assert plugin == p
        call_list.append(test2)
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test2',
        'params': {'name': 'World'}
    }
    p._dispatch(request)
    assert call_list == [test1, test2]

    @p.method("test3")
    def test3(name, request):
        """Also asks for the request instance. """
        assert request is not None
        call_list.append(test3)
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test3',
        'params': {'name': 'World'}
    }
    p._dispatch(request)
    assert call_list == [test1, test2, test3]

    @p.method("test4")
    def test4(name):
        """Try the positional arguments."""
        assert name == 'World'
        call_list.append(test4)
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test4',
        'params': ['World']
    }
    p._dispatch(request)
    assert call_list == [test1, test2, test3, test4]

    @p.method("test5")
    def test5(name, request, plugin):
        """Try the positional arguments, mixing in the request and plugin."""
        assert name == 'World'
        assert request is not None
        assert p == plugin
        call_list.append(test5)
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test5',
        'params': ['World']
    }
    p._dispatch(request)
    assert call_list == [test1, test2, test3, test4, test5]

    answers = []

    @p.method("test6")
    def test6(name, answer=42):
        """This method has a default value for one of its params"""
        assert name == 'World'
        answers.append(answer)
        call_list.append(test6)

    # Both calls should work (with and without the default param
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test6',
        'params': ['World']
    }
    p._dispatch(request)
    assert call_list == [test1, test2, test3, test4, test5, test6]
    assert answers == [42]

    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test6',
        'params': ['World', 31337]
    }
    p._dispatch(request)
    assert call_list == [test1, test2, test3, test4, test5, test6, test6]
    assert answers == [42, 31337]


def test_methods_errors():
    """A bunch of tests that should fail calling the methods."""
    call_list = []
    p = Plugin(autopatch=False)

    # Fails because we haven't added the method yet
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': {}
    }
    with pytest.raises(ValueError):
        p._dispatch(request)
    assert call_list == []

    @p.method("test1")
    def test1(name):
        call_list.append(test1)

    # Attempting to add it twice should fail
    with pytest.raises(ValueError):
        p.add_method("test1", test1)

    # Fails because it is missing the 'name' argument
    request = {'id': 1, 'jsonrpc': '2.0', 'method': 'test1', 'params': {}}
    with pytest.raises(TypeError):
        p._dispatch(request)
    assert call_list == []

    # The same with positional arguments
    request = {'id': 1, 'jsonrpc': '2.0', 'method': 'test1', 'params': []}
    with pytest.raises(TypeError):
        p._dispatch(request)
    assert call_list == []

    # Fails because we have a non-matching argument
    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': {'name': 'World', 'extra': 1}
    }
    with pytest.raises(TypeError):
        p._dispatch(request)
    assert call_list == []

    request = {
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'test1',
        'params': ['World', 1]
    }
    with pytest.raises(TypeError):
        p._dispatch(request)
    assert call_list == []
