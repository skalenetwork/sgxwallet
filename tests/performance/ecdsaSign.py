import asyncio
import argparse
import secrets
from typing import Any, Dict, List
from utils.performance_test import PerformanceTest


class EcdsaSignTest(PerformanceTest):
    """Performance test for ECDSA signature operations"""
    
    name = "EcdsaSign"
    method = "ecdsaSignMessageHash"
    xlabel = "Number of Threads"
    ylabel = "Throughput (ops/sec)"
    
    # ECDSA sign is a single operation per request
    default_batch_sizes = [1]  # Single operation per request
    default_parallel_threads = [1, 2, 4, 8, 16]
    default_parallel_batch_size = 1  # Single operation per request
    default_iterations = 100  # More iterations for better statistics
    default_warmup_iterations = 5

    # Pre-generated hashes for testing
    HASH_POOL_SIZE = 10000

    def __init__(self, ip: str, args: argparse.Namespace = None):
        super().__init__(ip, args)
        self.base = getattr(args, 'base', None) or 16
        # Pre-generated hash pool
        self._hash_pool: List[str] = []
        self._hash_index = 0

    @classmethod
    def add_test_args(cls, parser: argparse.ArgumentParser):
        """Add ECDSA-specific arguments"""
        parser.add_argument("--base", type=int, default=16, 
                            help="Numeric base for message hash (default: 16)")

    async def initialize(self):
        """Initialize including pre-generating hashes"""
        await super().initialize()
        print(f"Pre-generating {self.HASH_POOL_SIZE} message hashes...")
        self._hash_pool = [secrets.token_hex(32) for _ in range(self.HASH_POOL_SIZE)]
        self._hash_index = 0
        print("Pre-generation complete.")

    def _get_next_hash(self) -> str:
        """Get next pre-generated hash (wraps around)"""
        h = self._hash_pool[self._hash_index % len(self._hash_pool)]
        self._hash_index += 1
        return h

    def create_payload(self, var: int = 1, **kwargs) -> Dict[str, Any]:
        """Create ECDSA sign payload with unique message hash"""
        return {
            "base": self.base,
            "keyName": self.keys["ecdsa"]["name"],
            "messageHash": self._get_next_hash()
        }


if __name__ == "__main__":
    asyncio.run(EcdsaSignTest.main())
