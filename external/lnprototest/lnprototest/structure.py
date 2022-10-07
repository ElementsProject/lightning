#! /usr/bin/python3
import io
from .event import Event, ExpectMsg, ResolvableBool
from .errors import SpecFileError, EventError
from .namespace import namespace
from pyln.proto.message import Message
from typing import Union, List, Optional, TYPE_CHECKING, cast

if TYPE_CHECKING:
    # Otherwise a circular dependency
    from .runner import Runner, Conn

# These can all be fed to a Sequence() initializer.
SequenceUnion = Union["Sequence", List[Event], Event]


class Sequence(Event):
    """A sequence of ordered events"""

    def __init__(
        self,
        events: Union["Sequence", List[Event], Event],
        enable: ResolvableBool = True,
    ):
        """Events can be a Sequence, a single Event, or a list of Events.  If
        enable is False, this turns into a noop (e.g. if runner doesn't support
        it)."""
        super().__init__()
        self.enable = enable
        if type(events) is Sequence:
            # mypy gets upset because Sequence isn't defined yet.
            self.events = events.events  # type: ignore
            self.enable = events.enable  # type: ignore
            self.name = events.name  # type: ignore
        elif isinstance(events, Event):
            self.events = [events]
        else:
            self.events = events

    def enabled(self, runner: "Runner") -> bool:
        return self.resolve_arg("enable", runner, self.enable)

    def action(self, runner: "Runner", skip_first: bool = False) -> bool:
        super().action(runner)
        all_done = True
        for e in self.events:
            if not e.enabled(runner):
                continue
            if skip_first:
                skip_first = False
            else:
                all_done &= e.action(runner)
        return all_done

    @staticmethod
    def ignored_by_all(
        msg: Message, sequences: List["Sequence"]
    ) -> Optional[List[Message]]:
        # If they all say the same thing, that's the answer.
        rets = [cast(ExpectMsg, s.events[0]).ignore(msg) for s in sequences]
        if all([ignored == rets[0] for ignored in rets[1:]]):
            return rets[0]
        return None

    @staticmethod
    def match_which_sequence(
        runner: "Runner", msg: Message, sequences: List["Sequence"]
    ) -> Optional["Sequence"]:
        """Return which sequence expects this msg, or None"""

        for s in sequences:
            failreason = cast(ExpectMsg, s.events[0]).message_match(runner, msg)
            if failreason is None:
                return s

        return None


class OneOf(Event):
    """Event representing multiple possible sequences, one of which should happen"""

    def __init__(self, *args: SequenceUnion):
        super().__init__()
        self.sequences = []
        for s in args:
            seq = Sequence(s)
            if len(seq.events) == 0:
                raise ValueError("{} is an empty sequence".format(s))
            self.sequences.append(seq)

    def enabled_sequences(self, runner: "Runner") -> List[Sequence]:
        """Returns all enabled sequences"""
        return [s for s in self.sequences if s.enabled(runner)]

    def action(self, runner: "Runner") -> bool:
        super().action(runner)

        # Check they all use the same conn!
        conn: Optional[Conn] = None
        for s in self.sequences:
            c = cast(ExpectMsg, s.events[0]).find_conn(runner)
            if conn is None:
                conn = c
            elif c != conn:
                raise SpecFileError(self, "sequences do not all use the same conn?")
        assert conn

        while True:
            event = self.sequences[0].events[0]
            binmsg = runner.get_output_message(conn, event)
            if binmsg is None:
                raise EventError(self, f"Did not receive a message {event} from runner")

            try:
                msg = Message.read(namespace(), io.BytesIO(binmsg))
            except ValueError as ve:
                raise EventError(self, "Invalid msg {}: {}".format(binmsg.hex(), ve))

            ignored = Sequence.ignored_by_all(msg, self.enabled_sequences(runner))
            # If they gave us responses, send those now.
            if ignored is not None:
                for msg in ignored:
                    binm = io.BytesIO()
                    msg.write(binm)
                    runner.recv(self, conn, binm.getvalue())
                continue

            seq = Sequence.match_which_sequence(
                runner, msg, self.enabled_sequences(runner)
            )
            if seq is not None:
                # We found the sequence, run it
                return seq.action(runner, skip_first=True)

            raise EventError(
                self,
                "None of the sequences {} matched {}".format(
                    self.enabled_sequences(runner), msg.to_str()
                ),
            )


class AnyOrder(Event):
    """Event representing multiple sequences, all of which should happen, but not defined which order they would happen"""

    def __init__(self, *args: SequenceUnion):
        super().__init__()
        self.sequences = []
        for s in args:
            seq = Sequence(s)
            if len(seq.events) == 0:
                raise ValueError("{} is an empty sequence".format(s))
            self.sequences.append(seq)

    def enabled_sequences(self, runner: "Runner") -> List[Sequence]:
        """Returns all enabled sequences"""
        return [s for s in self.sequences if s.enabled(runner)]

    def action(self, runner: "Runner") -> bool:
        super().action(runner)

        # Check they all use the same conn!
        conn = None
        for s in self.sequences:
            c = cast(ExpectMsg, s.events[0]).find_conn(runner)
            if conn is None:
                conn = c
            elif c != conn:
                raise SpecFileError(self, "sequences do not all use the same conn?")
        assert conn

        all_done = True
        sequences = self.enabled_sequences(runner)
        while sequences != []:
            # Get message
            binmsg = runner.get_output_message(conn, sequences[0].events[0])
            if binmsg is None:
                raise EventError(
                    self,
                    "Did not receive a message from runner, still expecting {}".format(
                        [s.events[0] for s in sequences]
                    ),
                )

            try:
                msg = Message.read(namespace(), io.BytesIO(binmsg))
            except ValueError as ve:
                raise EventError(self, "Invalid msg {}: {}".format(binmsg.hex(), ve))

            ignored = Sequence.ignored_by_all(msg, self.enabled_sequences(runner))
            # If they gave us responses, send those now.
            if ignored is not None:
                for msg in ignored:
                    binm = io.BytesIO()
                    msg.write(binm)
                    runner.recv(self, conn, binm.getvalue())
                continue

            seq = Sequence.match_which_sequence(runner, msg, sequences)
            if seq is not None:
                sequences.remove(seq)
                all_done &= seq.action(runner, skip_first=True)
                continue

            raise EventError(
                self,
                "Message did not match any sequences {}: {}".format(
                    [s.events[0] for s in sequences], msg.to_str()
                ),
            )
        return all_done


class TryAll(Event):
    """Event representing multiple sequences, each of which should be tested"""

    def __init__(self, *args: SequenceUnion):
        super().__init__()
        self.sequences = [Sequence(s) for s in args]
        self.done = [False] * len(self.sequences)

    def action(self, runner: "Runner") -> bool:
        super().action(runner)

        # Take first undone one, or if that fails, first enabled one.
        first_enabled = None
        first_undone = None
        all_done = True
        for i, s in enumerate(self.sequences):
            if not s.enabled(runner):
                continue
            if not first_enabled:
                first_enabled = s
            if self.done[i]:
                continue
            if not first_undone:
                first_undone = s
                self.done[i] = True
            else:
                all_done = False

        # Note: they might *all* be disabled!
        if first_undone:
            first_undone.action(runner)
        elif first_enabled:
            first_enabled.action(runner)

        return all_done


def test_empty_sequence() -> None:
    class nullrunner(object):
        class dummyconfig(object):
            def getoption(self, name: str) -> bool:
                return False

        def __init__(self) -> None:
            self.config = self.dummyconfig()

    # This sequence should be tried twice.
    seq = Sequence(TryAll([], []))
    assert seq.action(nullrunner()) is False  # type: ignore
    assert seq.action(nullrunner()) is True  # type: ignore
