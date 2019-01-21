from typing import Any, List, Mapping, Optional, TypeVar, Type

T = TypeVar('T')
def force(value: Any, typ: Type[T]) -> T:
    if not isinstance(value, typ):
        raise TypeError(f'Expected {typ}, got {type(value)}')
    return value
