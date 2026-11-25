"""The "hashing trick" used by the EMBER2024 features, without scikit-learn.

thrember uses sklearn.feature_extraction.FeatureHasher(n, input_type=..., alternate_sign=...)
.transform([sample]).toarray()[0]. This module does exactly what scikit-learn 1.x does there
(sklearn/feature_extraction/_hashing_fast.pyx and scipy's sum_duplicates):

  - each feature name is UTF-8 encoded (bytes are used as they are) and hashed with
    MurmurHash3 x86 32-bit, seed 0, read as a signed 32-bit number h;
  - index = abs(h) % n_features, except h == -2**31: (2**31 - 1 - (n_features - 1)) % n_features;
  - value: 1 for "string" input; for "pair" input the pair's number, or 1 with the name
    "name=value" when the value is a string; a value of 0 is skipped;
  - alternate_sign: the value is multiplied by +1 when h >= 0, else -1;
  - values that land on the same index are added in float64 by scipy's own csr sum_duplicates()
    (scipy comes with LightGBM anyway), exactly as sklearn does: the order of that addition is
    scipy's, so it is copied by calling scipy rather than re-written.

tools/ml_compare_upstream.py checks this against scikit-learn on random input, and the tests
check fixed MurmurHash3 values.
"""
from __future__ import annotations

from functools import lru_cache

import numpy as np
from scipy import sparse as _sparse

_M32 = 0xFFFFFFFF
_C1 = 0xCC9E2D51
_C2 = 0x1B873593


def murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3_x86_32 of `data`, as a signed 32-bit integer (sklearn's murmurhash3_32 with
    positive=False)."""
    n = len(data)
    h = seed & _M32
    nblocks = n // 4
    if nblocks:
        for k in memoryview(data[: nblocks * 4]).cast("I"):   # little-endian on Windows/x86
            k = (k * _C1) & _M32
            k = ((k << 15) | (k >> 17)) & _M32
            k = (k * _C2) & _M32
            h ^= k
            h = ((h << 13) | (h >> 19)) & _M32
            h = (h * 5 + 0xE6546B64) & _M32
    rem = n & 3
    if rem:
        tail = nblocks * 4
        k = 0
        if rem >= 3:
            k ^= data[tail + 2] << 16
        if rem >= 2:
            k ^= data[tail + 1] << 8
        k ^= data[tail]
        k = (k * _C1) & _M32
        k = ((k << 15) | (k >> 17)) & _M32
        k = (k * _C2) & _M32
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _M32
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


@lru_cache(maxsize=1 << 16)
def _hash_name(name) -> int:
    if isinstance(name, str):
        name = name.encode("utf-8")
    elif not isinstance(name, bytes):
        raise TypeError("feature names must be strings")
    return murmurhash3_32(name, 0)


class _Rows:
    def __init__(self, array: np.ndarray):
        self._array = array

    def toarray(self) -> np.ndarray:
        return self._array


class FeatureHasher:
    """The part of sklearn's FeatureHasher that thrember uses (dtype float64)."""

    def __init__(self, n_features: int = 2**20, *, input_type: str = "dict",
                 alternate_sign: bool = True):
        if input_type not in ("string", "pair"):
            raise ValueError("only input_type 'string' and 'pair' are used by the EMBER features")
        self.n_features = int(n_features)
        self.input_type = input_type
        self.alternate_sign = alternate_sign

    def _index(self, h: int) -> int:
        n = self.n_features
        if h == -2147483648:
            return (2147483647 - (n - 1)) % n
        return abs(h) % n

    def transform(self, raw_X) -> _Rows:
        indices: list[int] = []
        values: list[float] = []
        indptr = [0]
        for x in raw_X:
            if isinstance(x, str):
                raise ValueError("Samples can not be a single string. The input must be an "
                                 "iterable over iterables of strings.")
            if self.input_type == "string":
                pairs = ((f, 1) for f in x)
            else:
                pairs = x
            for f, v in pairs:
                if isinstance(v, str):
                    f = f"{f}={v}"
                    value = 1
                else:
                    value = v
                if value == 0:
                    continue
                h = _hash_name(f)
                value = float(value)               # sklearn: a C double
                if self.alternate_sign and h < 0:
                    value = -value
                indices.append(self._index(h))
                values.append(value)
            indptr.append(len(indices))
        if len(indptr) == 1:
            raise ValueError("Cannot vectorize empty sequence.")
        if indices:
            # The same scipy steps as sklearn (sort the indices, then add duplicates), so values
            # that share an index are added in exactly the same order as upstream.
            m = _sparse.csr_array((np.array(values, dtype=np.float64), np.array(indices, dtype=np.int32),
                                   np.array(indptr, dtype=np.int64)),
                                  dtype=np.float64, shape=(len(indptr) - 1, self.n_features))
            m.sum_duplicates()
            return _Rows(m.toarray())
        return _Rows(np.zeros((len(indptr) - 1, self.n_features), dtype=np.float64))
