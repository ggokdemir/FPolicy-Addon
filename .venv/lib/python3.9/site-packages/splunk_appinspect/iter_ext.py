# Copyright 2019 Splunk Inc. All rights reserved.
from functools import reduce


def unique(a: list) -> list:
    """return the list with duplicate elements removed."""
    return list(set(a))


def intersect(a: list, b: list) -> list:
    """return the intersection of two lists."""
    return list(set(a) & set(b))


def union(a: list, b: list) -> list:
    """return the union of two lists."""
    return list(set(a) | set(b))


def count_iter(iterator: list) -> int:
    """Returns a count of items, yielded by an iterator."""
    return reduce(lambda acc, x: acc + 1, iterator, 0)
