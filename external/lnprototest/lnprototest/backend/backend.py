#! /usr/bin/python3
# This script exercises the backend implementation

# Released by Rusty Russell under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/
from abc import ABC, abstractmethod


class Backend(ABC):
    """
    Generic implementation of Bitcoin backend
    This is useful when the LN node uses different type
    of bitcoin backend.
    """

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def restart(self) -> None:
        pass
