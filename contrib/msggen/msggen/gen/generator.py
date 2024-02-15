"""
Generator interface!

author: https://github.com/vincenzopalazzo
"""

from abc import ABC, abstractmethod

from msggen.model import Service


class IGenerator(ABC):
    """
    Chain of responsibility handler that need to be
    implemented by all the generators.
    """

    @abstractmethod
    def generate(self, service: Service):
        pass


class GeneratorChain:
    """
    Chain responsibility pattern implementation to generalize
    the generation method.
    """

    def __init__(self):
        self.generators = []

    def add_generator(self, generator: IGenerator) -> None:
        self.generators.append(generator)

    def generate(self, service: Service) -> None:
        for _, generator in enumerate(self.generators):
            generator.generate(service)
