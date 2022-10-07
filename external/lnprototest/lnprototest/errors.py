#! /usr/bin/python3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .event import Event


class EventError(Exception):
    """Error thrown when the runner fails in some way"""

    def __init__(self, event: "Event", message: str):
        self.eventpath = [event]
        self.message = message

    def add_path(self, event: "Event") -> None:
        self.eventpath = [event] + self.eventpath


class SpecFileError(Exception):
    """Error thrown when the specification file has an error"""

    def __init__(self, event: "Event", message: str):
        self.event = event
        self.message = message
