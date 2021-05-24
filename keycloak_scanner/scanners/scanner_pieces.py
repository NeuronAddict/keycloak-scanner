from typing import Generic, TypeVar

T = TypeVar('T')
U = TypeVar('U')
V = TypeVar('V')
W = TypeVar('W')


class Need(Generic[T]):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def perform(self, dependency1: T, **kwargs):
        super().perform(**kwargs)


class Need2(Generic[T, U]):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def perform(self, dependency1: T, dependency2: U, **kwargs):
        super().perform(**kwargs)


class Need3(Generic[T, U, V]):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def perform(self, dependency1: T, dependency2: U, dependency3: V, **kwargs):
        super().perform(**kwargs)


class Need4(Generic[T, U, V, W]):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def perform(self, dependency1: T, dependency2: U, dependency3: V, dependency4: W, **kwargs):
        super().perform(**kwargs)
