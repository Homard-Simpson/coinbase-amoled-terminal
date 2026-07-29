from __future__ import annotations

import unittest

from coinbase_amoled_bridge.ratelimit import ClientHasher, TokenBucketLimiter


class Clock:
    value = 0.0

    def __call__(self) -> float:
        return self.value


class RateLimitTests(unittest.TestCase):
    def test_token_bucket_burst_retry_and_refill(self) -> None:
        clock = Clock()
        limiter = TokenBucketLimiter(60, 2, clock=clock)
        self.assertEqual(limiter.allow("client"), (True, 0))
        self.assertEqual(limiter.allow("client"), (True, 0))
        allowed, retry = limiter.allow("client")
        self.assertFalse(allowed)
        self.assertEqual(retry, 1)
        clock.value += 1
        self.assertEqual(limiter.allow("client"), (True, 0))

    def test_clients_are_independent_and_hash_is_stable_per_process(self) -> None:
        limiter = TokenBucketLimiter(1, 1, clock=Clock())
        self.assertTrue(limiter.allow("a")[0])
        self.assertFalse(limiter.allow("a")[0])
        self.assertTrue(limiter.allow("b")[0])
        hasher = ClientHasher(b"x" * 32)
        self.assertEqual(hasher.digest("127.0.0.1"), hasher.digest("127.0.0.1"))
        self.assertNotIn("127.0.0.1", hasher.digest("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
