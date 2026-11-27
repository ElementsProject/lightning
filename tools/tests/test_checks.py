#!/usr/bin/env python3
"""The spec for the tools/check-*.py source checkers.

Each case here shows a contributor (or their agent) exactly what the
checkers accept and reject, so nobody has to guess from the regexes.

Plain tests document behaviour the checkers promise today.  Tests marked
xfail(strict=True) document known gaps: behaviour we want but do not have
yet.  When a gap is fixed, its xfail starts passing and pytest fails the
run, so the marker must be removed with the fix.

Run with: uv run pytest tools/tests/test_checks.py
"""
import importlib.util
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent


def load(name):
    """Import a hyphenated tools/ script as a module."""
    modname = name.replace('-', '_')
    spec = importlib.util.spec_from_file_location(modname, TOOLS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


check_comments = load('check-comments')
check_commit_msgs = load('check-commit-msgs')
check_switch_default = load('check-switch-default')
check_tab_indent = load('check-tab-indent')
check_take_parent = load('check-take-parent')
check_unused_functions = load('check-unused-functions')


# ----------------------------------------------------------------------
# check-comments: added comments must describe the code, not the change.
# ----------------------------------------------------------------------

def comment_complaints(text, path='x.c', added=None):
    """Complaints for `text`; by default every line counts as added."""
    if added is None:
        added = set(range(1, text.count('\n') + 2))
    return [complaint for _, complaint in
            check_comments.problems(path, text, added)]


GOOD_COMMENTS = [
    pytest.param('/* Send the message to the peer. */\n',
                 id='describes-the-code'),
    pytest.param('/* We sign this commitment and revoke the old one. */\n',
                 id='commitment-is-not-a-git-commit'),
    pytest.param('/* BOLT #2:\n' + ' * quoted spec text\n' * 10 + ' */\n',
                 id='bolt-quote-may-be-long'),
    pytest.param('/*~ This walkthrough comment teaches the reader,\n'
                 + ' * and tutorial prose takes room.\n' * 10 + ' */\n',
                 id='tutorial-comment-may-be-long'),
    pytest.param('\t/* one\n\t * two\n\t * three\n\t * four */\n',
                 id='indented-four-lines-is-at-the-limit'),
]

BAD_COMMENTS = [
    pytest.param('/* This fix handles the crash. */\n',
                 id='narrates-the-change'),
    pytest.param('/* The old implementation used a list. */\n',
                 id='describes-removed-code'),
    pytest.param('/* See PR #9748 for details. */\n',
                 id='cites-a-pull-request'),
    pytest.param('/* Added per review feedback. */\n',
                 id='cites-a-review'),
    pytest.param('/* See channeld/channeld.c:123 for the caller. */\n',
                 id='points-at-a-line-number'),
    pytest.param('/* one\n' + ' * filler\n' * 7 + ' */\n',
                 id='nine-lines-at-margin-is-over-the-limit'),
    pytest.param('\t/* one\n\t * two\n\t * three\n\t * four\n\t * five */\n',
                 id='five-indented-lines-is-over-the-limit'),
    pytest.param('/* kept per review; BOLT semantics unchanged */\n',
                 id='the-word-bolt-is-not-an-exemption'),
]


@pytest.mark.parametrize('text', GOOD_COMMENTS)
def test_good_comments(text):
    assert comment_complaints(text) == []


@pytest.mark.parametrize('text', BAD_COMMENTS)
def test_bad_comments(text):
    assert comment_complaints(text) != []


@pytest.mark.xfail(strict=True, reason='"this commit tx" is a commitment'
                   ' transaction, not a git commit')
def test_commit_tx_is_not_a_git_commit():
    assert comment_complaints('/* Sign this commit tx. */\n') == []


@pytest.mark.xfail(strict=True, reason='the style guide endorses FIXME:'
                   ' refactor notes')
def test_fixme_refactor_is_allowed():
    assert comment_complaints('/* FIXME: refactor into common/ */\n') == []


@pytest.mark.xfail(strict=True, reason='"as requested by the peer" is'
                   ' protocol prose, not review prose')
def test_peer_requests_are_not_review_requests():
    assert comment_complaints(
        '/* As requested by the peer, forget the channel. */\n') == []


@pytest.mark.xfail(strict=True, reason='editing one line of an existing'
                   ' long comment should not fail the whole comment')
def test_partial_edit_of_long_comment():
    text = '/* one\n' + ' * filler\n' * 10 + ' */\n'
    assert comment_complaints(text, added={5}) == []


# ----------------------------------------------------------------------
# check-commit-msgs: a message must stand on its own after the PR is gone.
# ----------------------------------------------------------------------

def msg_complaints(message):
    return list(check_commit_msgs.problems(message))


GOOD_MESSAGES = [
    pytest.param('wallet: fix incorrect channel_htlcs id migration\n'
                 '\nThe migration wrote ids from the wrong table.\n',
                 id='subsystem-intent-with-body'),
    pytest.param('connectd, lightningd: ignore unknown channel errors\n'
                 '\nBoth daemons see them.\n',
                 id='two-subsystems-are-fine'),
    pytest.param('Revert "wallet: fix incorrect migration"\n'
                 '\nIt broke replays.\n',
                 id='reverts-keep-gits-own-subject'),
    pytest.param('lightningd: quote the crash\n\nThe log said:\n\n'
                 '  ' + 'x' * 100 + '\n',
                 id='indented-quoted-output-may-be-wide'),
    pytest.param('doc: link the spec\n\n'
                 'https://github.com/lightning/bolts/blob/master/'
                 '02-peer-protocol.md#channel-establishment-v2\n',
                 id='urls-may-be-wide'),
    pytest.param('wallet: fix migration\n\nWhy.\n\n'
                 'Changelog-Fixed: wallet: ' + 'x' * 70 + '\n',
                 id='trailers-may-be-wide'),
    pytest.param('build: use -Werror on debug builds\n\nWhy.\n',
                 id='build-is-a-real-subsystem'),
]

BAD_MESSAGES = [
    pytest.param('Fix the crash\n\nBody.\n',
                 id='no-subsystem-prefix'),
    pytest.param('wallet: fix migration\nBody with no blank line.\n',
                 id='no-blank-line-after-subject'),
    pytest.param('doc: update\n\n# Overview\n\nText.\n',
                 id='markdown-headers'),
    pytest.param('wallet: fix migration\n\n' + 'word ' * 20 + '\n',
                 id='prose-wider-than-80-columns'),
    pytest.param('wallet: fix migration\n\n'
                 'Changed as discussed in the review.\n',
                 id='refers-to-the-review'),
    pytest.param('wallet: fix migration\n\n'
                 'The previous commit added the table.\n',
                 id='refers-to-a-commit-by-position'),
    pytest.param('wallet: fix migration\n\n' + 'A line of prose.\n' * 11,
                 id='paragraph-longer-than-ten-lines'),
    pytest.param('fixup! wallet: fix incorrect migration\n',
                 id='unfolded-fixups-do-not-merge'),
    pytest.param('squash! wallet: fix incorrect migration\n',
                 id='unfolded-squashes-do-not-merge'),
    pytest.param('fix: release txprepare reservations on send failure\n',
                 id='fix-is-a-kind-of-change-not-a-subsystem'),
    pytest.param('chore(deps): bump pyln-client\n',
                 id='conventional-commit-scopes-are-not-subsystems'),
    pytest.param('Feat: enhance JUnit XML reporting\n',
                 id='change-types-are-rejected-in-any-case'),
]


@pytest.mark.parametrize('message', GOOD_MESSAGES)
def test_good_messages(message):
    assert msg_complaints(message) == []


@pytest.mark.parametrize('message', BAD_MESSAGES)
def test_bad_messages(message):
    assert msg_complaints(message) != []


def test_prose_subject_is_not_a_subsystem():
    assert msg_complaints('I Fixed This: lol\n\nBody.\n') != []


def test_subject_length_is_capped():
    assert msg_complaints('wallet: ' + 'long ' * 20 + '\n\nBody.\n') != []


@pytest.mark.xfail(strict=True, reason='"the last commit tx" is a commitment'
                   ' transaction, not a git commit')
def test_commit_tx_in_message_is_not_by_position():
    assert msg_complaints('channeld: resend the last commit tx\n\n'
                          'We retransmit the last commit tx we signed.\n') == []


# ----------------------------------------------------------------------
# check-switch-default: a switch over an enum lists every case.
# ----------------------------------------------------------------------

def switch_hits(code, names=frozenset()):
    return list(check_switch_default.enum_defaults(
        check_switch_default.code_only(code), names))


def test_default_in_enum_switch_is_rejected():
    code = ('void f(enum color c)\n{\n'
            '\tswitch (c) {\n'
            '\tcase COLOR_RED:\n\t\tbreak;\n'
            '\tdefault:\n\t\tbreak;\n'
            '\t}\n}\n')
    assert switch_hits(code, {'COLOR_RED', 'COLOR_BLUE'}) != []


def test_wire_cases_count_as_enum_without_harvest():
    code = ('void f(int t)\n{\n'
            '\tswitch (t) {\n'
            '\tcase WIRE_PING:\n\t\tbreak;\n'
            '\tdefault:\n\t\tbreak;\n'
            '\t}\n}\n')
    assert switch_hits(code) != []


def test_errno_switch_keeps_its_default():
    code = ('void f(int e)\n{\n'
            '\tswitch (e) {\n'
            '\tcase EINTR:\n\t\tbreak;\n'
            '\tdefault:\n\t\tbreak;\n'
            '\t}\n}\n')
    assert switch_hits(code, {'COLOR_RED'}) == []


def test_exhaustive_enum_switch_passes():
    code = ('void f(enum color c)\n{\n'
            '\tswitch (c) {\n'
            '\tcase COLOR_RED:\n\tcase COLOR_BLUE:\n\t\tbreak;\n'
            '\t}\n}\n')
    assert switch_hits(code, {'COLOR_RED', 'COLOR_BLUE'}) == []


def test_inner_integer_switch_keeps_its_default():
    code = ('void f(enum color c, int x)\n{\n'
            '\tswitch (c) {\n'
            '\tcase COLOR_RED: {\n'
            '\t\tswitch (x) {\n'
            '\t\tcase 3:\n\t\t\tbreak;\n'
            '\t\tdefault:\n\t\t\tbreak;\n'
            '\t\t}\n'
            '\t\tbreak;\n'
            '\t}\n'
            '\t}\n}\n')
    assert switch_hits(code, {'COLOR_RED'}) == []


# ----------------------------------------------------------------------
# check-take-parent: take() gives its argument away, so allocate off NULL.
# ----------------------------------------------------------------------

def take_hits(code):
    return [m.group(1) or m.group(2) for m in check_take_parent.TAKE.finditer(
        check_take_parent.code_only(code))]


def test_take_of_null_allocation_passes():
    assert take_hits('send(p, take(towire_foo(NULL, x)));\n') == []


def test_take_of_tmpctx_allocation_is_rejected():
    assert take_hits('send(p, take(towire_foo(tmpctx, x)));\n') == ['tmpctx']


def test_take_of_tal_with_parent_is_rejected():
    assert take_hits('send(p, take(tal_dup(peer, u8, m)));\n') == ['peer']


@pytest.mark.xfail(strict=True, reason='the two-line form from the style'
                   ' guide is not caught yet')
def test_take_of_variable_allocated_off_tmpctx():
    code = 'msg = towire_foo(tmpctx, x);\nsend(p, take(msg));\n'
    assert take_hits(code) != []


def wire_take_hits(code):
    return list(check_take_parent.wire_takes(
        check_take_parent.code_only(code)))


def test_take_wrapping_a_wire_call_passes():
    assert wire_take_hits('send(p, take(towire_foo(NULL, x)));\n') == []


def test_take_inside_a_wire_call_is_rejected():
    assert wire_take_hits('msg = towire_foo(NULL, take(script));\n') != []


def test_take_inside_a_fromwire_call_is_rejected():
    assert wire_take_hits('ok = fromwire_foo(ctx, take(msg), &x);\n') != []


# ----------------------------------------------------------------------
# check-tab-indent: C code is indented with tabs; spaces only align a
# continuation under the line before.
# ----------------------------------------------------------------------

def indent_hits(code):
    return list(check_tab_indent.problems(
        check_tab_indent.code_only(code)))


def test_tab_indented_body_passes():
    assert indent_hits('void f(void)\n{\n\tg();\n}\n') == []


def test_space_indented_body_is_rejected():
    assert indent_hits('void f(void)\n{\n    g();\n}\n') != []


def test_space_before_tab_is_rejected():
    assert indent_hits('void f(void)\n{\n \tg();\n}\n') != []


def test_aligned_continuation_passes():
    code = ('static void subtract(const struct channel *channel,\n'
            '                     struct amount_msat *amount)\n'
            '{\n\tg();\n}\n')
    assert indent_hits(code) == []


def test_comment_interior_is_not_code():
    assert indent_hits('/* one\n * two\n */\nvoid f(void);\n') == []


def test_macro_continuation_passes():
    code = '#define F(x) do { \\\n        g(x); \\\n} while (0)\n'
    assert indent_hits(code) == []


# ----------------------------------------------------------------------
# check-unused-functions: a new non-static function needs a caller.
# ----------------------------------------------------------------------

def defined(code):
    return [name for _, name in check_unused_functions.definitions(
        check_unused_functions.code_only(code))]


def test_definition_at_margin_is_found():
    assert defined('int foo(int x)\n{\n\treturn x;\n}\n') == ['foo']


def test_static_definition_is_ignored():
    assert defined('static int foo(int x)\n{\n\treturn x;\n}\n') == []


def test_prototype_is_not_a_definition():
    assert defined('int foo(int x);\n') == []


def test_multiline_definition_is_found():
    assert 'foo' in defined('struct bar *\nfoo(int x)\n{\n\treturn NULL;\n}\n')


def test_indented_call_is_a_use():
    assert check_unused_functions.is_use('\tfoo(x);', 'foo')
    assert check_unused_functions.is_use('\treturn foo(x);', 'foo')
    assert check_unused_functions.is_use('\tif (!foo(x))', 'foo')


def test_declaration_at_margin_is_not_a_use():
    assert not check_unused_functions.is_use('int foo(int x);', 'foo')
    assert not check_unused_functions.is_use('void foo(void)', 'foo')


def test_indented_prototype_is_not_a_use():
    assert not check_unused_functions.is_use('\tvoid foo(int x);', 'foo')


def test_declaration_after_comment_is_not_a_use():
    line = '/* Helper for foo. */ void foo(int x);'
    assert not check_unused_functions.is_use(
        check_unused_functions.code_only(line), 'foo')
