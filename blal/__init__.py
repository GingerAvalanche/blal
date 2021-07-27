from typing import Union


class BLAL:
    def __init__(self, data: Union[bytes, dict], be: bool = False) -> None:
        if type(data) == bytes:
            self._from_bytes(data)
        elif type(data) == dict:
            self._from_yaml(data, be)

    def _from_bytes(self, data: bytes) -> None:
        if not data[:4] == b"BLAL":
            raise ValueError("Unknown BLAL magic")
        bom = data[4:6]
        self._be: bool = bom == b"\xfe\xff"
        if not self._be and not bom == b"\xff\xfe":
            raise ValueError("Invalid BOM")
        self._version: int = int.from_bytes(data[6:8], byteorder="little")
        if not self._version == 1:
            raise ValueError("Unknown BLAL version")
        bo = "big" if self._be else "little"
        self._num_hashes: int = int.from_bytes(data[8:12], bo)
        self._data: list = []
        for i in range(self._num_hashes):
            start = 12 + (i * 4)
            self._data.append(int.from_bytes(data[start : start + 4], bo))

    def _from_yaml(self, data: dict, be: bool) -> None:
        self._be: bool = be
        bo = "big" if be else "little"
        self._version: int = int(data["version"])
        self._num_hashes: int = len(data["Hashes"])
        self._data: list = []
        for hash in data["Hashes"]:
            try:
                val = int(hash)
            except ValueError:
                val = int(hash, 16)
            try:
                val.to_bytes(4, bo)
            except OverflowError:
                raise OverflowError(f"{val} data size is larger than 4 bytes")
            self._data.append(val)

    def to_bytes(self) -> bytes:
        bo = "big" if self._be else "little"
        arr = bytearray(b"BLAL")
        arr += bytearray(b"\xfe\xff") if self._be else bytearray(b"\xff\xfe")
        arr += self._version.to_bytes(2, "little")
        arr += self._num_hashes.to_bytes(4, bo)
        for i in range(self._num_hashes):
            arr += self._data[i].to_bytes(4, bo)
        ret = bytes(arr)
        del arr
        return ret

    def to_yaml(self) -> dict:
        ret: dict = {}
        ret["version"] = self._version
        ret["Hashes"] = [int(hash) for hash in self._data]
        return ret

    def add_int(self, add: int) -> None:
        int(add)
        try:
            add.to_bytes(4, "little")
        except OverflowError:
            raise OverflowError(f"{add} data size is larger than 4 bytes")
        self._num_hashes += 1
        self._data.append(add)
        self._data.sort()

    def add_hex(self, add: str) -> None:
        num = int(add, 16)
        try:
            num.to_bytes(4, "little")
        except OverflowError:
            raise OverflowError(f"{add} data size is larger than 4 bytes")
        self._num_hashes += 1
        self._data.append(num)
        self._data.sort()

    def remove(self, index: int) -> int:
        if not type(index) == int:
            raise TypeError(f"'{type(index)}' cannot be interpreted as an integer: {index}")
        if index > self._num_hashes:
            raise IndexError(f"remove index out of range: {index}")
        self._num_hashes -= 1
        return self._data.pop(index)
