import asyncio
import argparse
import time
import aiohttp
import matplotlib.pyplot as plt
import numpy as np
from typing import Any, Dict
from utils.performance_test import PerformanceTest


class EcdsaSignTest(PerformanceTest):
    """Performance test for ECDSA signature operations"""
    
    name = "EcdsaSign"
    method = "ecdsaSignMessageHash"
    xlabel = "Number of Threads"
    ylabel = "Throughput (ops/sec)"
    
    default_parallel_threads = [1, 2, 4, 8, 16]
    default_parallel_batch_size = 1

    def __init__(self, ip: str, args: argparse.Namespace = None):
        super().__init__(ip, args)
        self.base = getattr(args, 'base', None) or 16
        self.duration = getattr(args, 'duration', None) or 5  # seconds

    @classmethod
    def add_test_args(cls, parser: argparse.ArgumentParser):
        """Add ECDSA-specific arguments"""
        parser.add_argument("--base", type=int, default=16, 
                            help="Numeric base for message hash (default: 16)")
        parser.add_argument("--duration", type=int, default=5, 
                            help="Duration in seconds for ops/sec test (default: 5)")

    def create_payload(self, var: int = 1, **kwargs) -> Dict[str, Any]:
        """Create ECDSA sign payload with unique message hash"""
        import secrets
        # Use unique hash each time to avoid duplicate-detection delay
        unique_hash = secrets.token_hex(32)
        return {
            "base": self.base,
            "keyName": self.keys["ecdsa"]["name"],
            "messageHash": unique_hash
        }

    async def run(self):
        """Run ops/sec test for ECDSA signing"""
        print(f"Running ECDSA sign performance test (base={self.base})...")
        
        results = {}
        
        # Test each thread count
        for threads in self.parallel_threads:
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
    asyncio.run(EcdsaSignTest.main())
