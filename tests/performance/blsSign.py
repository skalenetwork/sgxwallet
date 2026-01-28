import asyncio
import argparse
import time
import aiohttp
import secrets
import matplotlib.pyplot as plt
import numpy as np
from typing import Any, Dict, List
from utils.performance_test import PerformanceTest


class BlsSignTest(PerformanceTest):
    """Performance test for BLS signature operations"""
    
    name = "BlsSign"
    method = "blsSignMessageHash"
    xlabel = "Number of Threads"
    ylabel = "Throughput (ops/sec)"
    
    default_parallel_threads = [1, 2, 4, 8, 16]
    default_parallel_batch_size = 1  # Single operation per request

    # Pre-generated hashes for testing
    HASH_POOL_SIZE = 10000  # Large enough for any test duration

    def __init__(self, ip: str, args: argparse.Namespace = None):
        super().__init__(ip, args)
        self.t = getattr(args, 't', None) or 2
        self.n = getattr(args, 'n', None) or 3
        self.duration = getattr(args, 'duration', None) or 5  # seconds
        # Pre-generated hash pool
        self._hash_pool: List[str] = []
        self._hash_index = 0

    @classmethod
    def add_test_args(cls, parser: argparse.ArgumentParser):
        """Add BLS-specific arguments"""
        parser.add_argument("-t", type=int, default=2, help="Threshold value for BLS (default: 2)")
        parser.add_argument("-n", type=int, default=3, help="Total nodes for BLS (default: 3)")
        parser.add_argument("--duration", type=int, default=5, help="Duration in seconds for ops/sec test (default: 5)")

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

    async def run(self):
        """Run ops/sec test for BLS signing"""
        print(f"Running BLS sign performance test (t={self.t}, n={self.n})...")
        
        results = {}
        
        # Test each thread count
        for threads in self.parallel_threads:
            # Reset hash index for each test to ensure unique hashes
            self._hash_index = 0
            result = await self.run_timed_ops_test(threads, self.duration)
            results[threads] = result['ops_per_sec']
            print(f"  {threads:2d} threads: {result['ops_per_sec']:6.1f} ops/sec ({result['ops']} ops in {self.duration}s)")
        
        # Save plot
        self._save_plot(results, f"plots/{self.name.lower()}-throughput.png")

    async def run_timed_ops_test(self, num_threads: int, duration_sec: int) -> Dict[str, float]:
        """Run test for a fixed duration, count operations"""
        connector = aiohttp.TCPConnector(ssl=None, limit=0, limit_per_host=0)
        ops = 0
        
        async with aiohttp.ClientSession(connector=connector) as session:
            start = time.perf_counter()
            end_time = start + duration_sec
            
            while time.perf_counter() < end_time:
                # Fire off concurrent requests
                tasks = [self.make_single_request(session, True, var=1) for _ in range(num_threads)]
                await asyncio.gather(*tasks)
                ops += num_threads
        
        elapsed = time.perf_counter() - start
        return {
            "ops_per_sec": ops / elapsed,
            "ops": ops,
            "elapsed_sec": elapsed
        }

    def _save_plot(self, results: Dict[int, float], filename: str):
        """Save throughput vs threads plot"""
        threads = list(results.keys())
        ops_per_sec = list(results.values())
        
        plt.figure(figsize=(10, 6))
        plt.plot(threads, ops_per_sec, marker='o', linewidth=2, markersize=8)
        plt.xlabel(self.xlabel)
        plt.ylabel(self.ylabel)
        plt.title(f"{self.name} Performance Test")
        plt.grid(True)
        plt.xticks(threads)
        plt.savefig(filename)
        plt.close()
        print(f"\nPlot saved to: {filename}")


if __name__ == "__main__":
    asyncio.run(BlsSignTest.main())
