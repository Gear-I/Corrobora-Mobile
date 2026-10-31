import hashlib
import random
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.evidence import ChunkedHasher, hash_file


def digest_of(data: bytes, chunk_size: int, split: list[int] | None = None):
    hasher = ChunkedHasher(chunk_size)
    pos = 0
    for cut in split or []:
        hasher.update(data[pos:cut])
        pos = cut
    hasher.update(data[pos:])
    return hasher.finish()


class ChunkedHasherTests(unittest.TestCase):
    def test_empty_stream(self):
        d = digest_of(b"", 4)
        self.assertEqual((d.size, d.sha256, d.chunks), (0, hashlib.sha256(b"").hexdigest(), ()))

    def test_chunks_cover_stream_exactly(self):
        data = bytes(range(10))
        d = digest_of(data, 4)
        self.assertEqual(d.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual([(c.index, c.offset, c.length) for c in d.chunks], [(0, 0, 4), (1, 4, 4), (2, 8, 2)])
        for c in d.chunks:
            self.assertEqual(c.sha256, hashlib.sha256(data[c.offset : c.offset + c.length]).hexdigest())

    def test_exact_multiple_has_no_empty_trailing_chunk(self):
        d = digest_of(b"x" * 8, 4)
        self.assertEqual([c.length for c in d.chunks], [4, 4])

    def test_boundaries_independent_of_how_stream_is_split(self):
        rng = random.Random(1234)
        data = rng.randbytes(1000)
        reference = digest_of(data, 37)
        for _ in range(25):
            cuts = sorted(rng.sample(range(1, len(data)), rng.randint(1, 30)))
            self.assertEqual(digest_of(data, 37, cuts), reference)

    def test_on_chunk_called_in_order_including_final_partial(self):
        seen = []
        hasher = ChunkedHasher(4, on_chunk=seen.append)
        hasher.update(b"abcdef")
        self.assertEqual([c.index for c in seen], [0])  # only complete chunks so far
        d = hasher.finish()
        self.assertEqual(list(d.chunks), seen)
        self.assertEqual(seen[-1].length, 2)

    def test_finish_is_idempotent_and_blocks_updates(self):
        hasher = ChunkedHasher(4)
        hasher.update(b"abc")
        first = hasher.finish()
        self.assertEqual(hasher.finish(), first)
        with self.assertRaises(ModelValidationError):
            hasher.update(b"d")

    def test_invalid_chunk_size(self):
        for bad in (0, -1, True, 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    ChunkedHasher(bad)  # type: ignore[arg-type]

    def test_hash_file_matches_streaming(self):
        data = random.Random(7).randbytes(3 * 1024 * 1024 + 5)  # larger than one read block
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.bin"
            path.write_bytes(data)
            self.assertEqual(hash_file(path, 1024 * 1024), digest_of(data, 1024 * 1024))


if __name__ == "__main__":
    unittest.main()
