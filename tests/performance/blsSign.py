import asyncio
import argparse
import secrets
from typing import Any, Dict, List
from utils.performance_test import PerformanceTest


class BlsSignTest(PerformanceTest):
    """Performance test for BLS signature operations"""
    
    name = "BlsSign"
    method = "blsSignMessageHash"
    xlabel = "Number of Threads"
    ylabel = "Throughput (ops/sec)"
    
    # BLS sign is a single operation per request, so serial batch test is less meaningful
    # Focus on parallel throughput test with variable thread counts
    default_batch_sizes = [1]  # Single operation per request
    default_parallel_threads = [1, 2, 4, 8, 16]
    default_parallel_batch_size = 1  # Single operation per request
    default_iterations = 100  # More iterations needed for single-op requests

    # Pre-generated hashes for testing
    HASH_POOL_SIZE = 10000  # Large enough for any test duration

    def __init__(self, ip: str, args: argparse.Namespace = None):
        super().__init__(ip, args)
        self.t = getattr(args, 't', None) or 15
        self.n = getattr(args, 'n', None) or 22
        # Pre-generated hash pool
        self._hash_pool: List[str] = []
        self._hash_index = 0

    @classmethod
    def add_test_args(cls, parser: argparse.ArgumentParser):
        """Add BLS-specific arguments"""
        parser.add_argument("-t", type=int, default=15, help="Threshold value for BLS (default: 15)")
        parser.add_argument("-n", type=int, default=22, help="Total nodes for BLS (default: 22)")

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
        """Create BLS sign payload with pre-generated message hash"""
        return {
            "keyShareName": self.keys["bls"]["name"],
            "messageHash": self._get_next_hash(),
            "t": self.t,
            "n": self.n
        }


if __name__ == "__main__":
    asyncio.run(BlsSignTest.main())
