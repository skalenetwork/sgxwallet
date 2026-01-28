import time
import asyncio
import argparse
import numpy as np
import aiohttp
import matplotlib.pyplot as plt
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from utils.sgx_key_utils import provision_keys


class Results:
    def __init__(self, rtt: int, rtt_std: int, mean_times: Dict[int, tuple[int, float]], 
                 std: Dict[int, float]):
        # get times only
        mean_times_updated = {k: v[1] for k, v in mean_times.items()}
        # get batch size only
        num_reqsts_sent = np.array([x[0] for x in mean_times.values()])
        self.x_vals = np.array(list(mean_times_updated.keys()))
        times_list = np.array(list(mean_times_updated.values()))

        times_without_rtt = times_list - rtt

        # 1000 -> convert from ms to seconds        
        self.y_vals = num_reqsts_sent / (times_without_rtt / 1000)

        y_std = np.array(list(std.values()))

        self.upper_bound = np.maximum(num_reqsts_sent / ((times_without_rtt + y_std) / 1000), 0)
        self.lower_bound = np.maximum(num_reqsts_sent / ((times_without_rtt - y_std) / 1000), 0)

        self.rtt_upper_bound_upper_std = np.maximum(num_reqsts_sent / ((times_without_rtt + y_std + rtt_std) / 1000), 0)
        self.rtt_upper_bound_lower_std = np.maximum(num_reqsts_sent / ((times_without_rtt + y_std - rtt_std) / 1000), 0)

        self.rtt_lower_bound_upper_std = np.maximum(num_reqsts_sent / ((times_without_rtt - y_std + rtt_std) / 1000), 0)
        self.rtt_lower_bound_lower_std = np.maximum(num_reqsts_sent / ((times_without_rtt - y_std - rtt_std) / 1000), 0)

    def plot(self, title: str, xlabel: str, ylabel: str, filename: str):
        plt.figure(figsize=(10, 6))
        # plot the main line
        plt.plot(self.x_vals, self.y_vals, marker='o')
        # plot the standard deviation area
        plt.fill_between(self.x_vals, self.upper_bound, self.lower_bound, color='blue', alpha=0.25, label='±1 Std Dev')
        # plot RTT bounds on the upper side of the area of the above area
        plt.fill_between(self.x_vals, self.rtt_upper_bound_upper_std, self.rtt_upper_bound_lower_std, color='red', alpha=0.5, label='RTT ± Std Dev')
        # plot RTT bounds on the lower side of the area of the above area
        plt.fill_between(self.x_vals, self.rtt_lower_bound_upper_std, self.rtt_lower_bound_lower_std, color='red', alpha=0.5, label='RTT ± Std Dev')
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.title(title)
        plt.grid(True)
        plt.savefig(f"./plots/{filename}.png")
        plt.show()
    

class PerformanceTest(ABC):
    """Base class for performance tests"""
    
    # Override these in subclasses
    name = "PerformanceTest"
    method = ""
    xlabel = "Variable"
    ylabel = "Throughput (ops/sec)"
    
    # Default test parameters (override in subclass)
    default_batch_sizes = [64, 128, 256, 512, 1024]
    default_parallel_threads = [1, 2, 4, 8, 11, 16]
    # number of times we call the method per iteration for a better mean
    default_iterations = 3
    default_parallel_batch_size = 500
    
    def __init__(self, ip: str, args: argparse.Namespace = None):
        self.endpoint = "http://" + ip + ":1029"
        self.args = args

        # Test parameters from args or defaults
        self.batch_sizes = self._parse_list(args, 'batch_sizes', self.default_batch_sizes)
        self.parallel_threads = self._parse_list(args, 'parallel_threads', self.default_parallel_threads)
        self.num_iterations = getattr(args, 'iterations', None) or self.default_iterations
        self.parallel_batch_size = getattr(args, 'parallel_batch_size', None) or self.default_parallel_batch_size

        # Initialized on 'create' method
        self.keys = None
        self.rtt = None
        self.rtt_std = None

    def _parse_list(self, args, attr: str, default: list) -> list:
        """Parse comma-separated string to list of ints"""
        val = getattr(args, attr, None) if args else None
        if val:
            return [int(x) for x in val.split(',')]
        return default

    @classmethod
    async def create(cls, ip: str, args: argparse.Namespace = None):
        """Async factory method to create and initialize the test"""
        instance = cls(ip, args)
        await instance.initialize()
        return instance
    
    async def initialize(self):
        """Initialize async components like RTT measurement and key provisioning"""
        if self.rtt is None:
            (self.rtt, self.rtt_std) = await self._measure_rtt()

        print("Generating keys...")
        self.keys = provision_keys(self.endpoint)
    
    async def _measure_rtt(self, num_samples: int = 50) -> tuple[float, float]:
        """Measure round-trip time with invalid requests"""
        print("Measuring RTT...")
        
        connector = aiohttp.TCPConnector(ssl=None)  

        async with aiohttp.ClientSession(connector = connector) as session:
            times = []
            for _ in range(num_samples):
                # Send invalid request to measure RTT
                _, elapsed = await self.make_single_request(session, False)
                times.append(elapsed)
        
        avg_rtt = np.mean(times)
        std_rtt = np.std(times)
        print(f"Average RTT: {avg_rtt:.2f} ms")
        return (avg_rtt, std_rtt)

    
    @abstractmethod
    def create_payload(self, var: int = 1, **kwargs) -> Dict[str, Any]:
        """Create the JSON-RPC params for this test. 'var' is the variable being tested."""
        pass

    def get_method_name(self) -> str:
        """Get JSON-RPC method name for this test"""
        return self.method
    
    async def make_single_request(self, session: aiohttp.ClientSession, valid: bool, **kwargs) -> tuple:
        """Make a single request and return (response, elapsed_time)"""

        payload = {}

        if valid:
            payload["jsonrpc"] = "2.0"
            payload["method"] = self.get_method_name()
            payload["params"] = self.create_payload(**kwargs)
            payload["id"] = 1
        else:
            payload["jsonrpc"] = "2.0"
            payload["method"] = {}
            payload["params"] = {}
            payload["id"] = 1
        
        start = time.perf_counter()
        async with session.post(self.endpoint, json=payload) as response:
            result = await response.json()
            end = time.perf_counter()
            
        return result, (end - start) * 1000 # Convert to ms
    
    async def run_parallel_test(self, num_threads: List[int], variable: int, num_iterations: int = 2, **kwargs) -> Results:
        """Run parallel throughput test with different thread counts"""
        print("Running parallel throughput test...")
        results = {}
        standard_devs = {}
        
        connector = aiohttp.TCPConnector(ssl=None, limit=0, limit_per_host=0)  # No connection limits
        async with aiohttp.ClientSession(connector=connector) as session:
            
            for threads in num_threads:
                times = []
                for _ in range(num_iterations):
                    start_time = time.perf_counter()
                    # Create N parallel tasks
                    tasks = [self.make_single_request(session, True, var=variable, **kwargs) for _ in range(threads)]
                    await asyncio.gather(*tasks)
                    total_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
                    times.append(total_time)
                
                results[threads] = (variable * threads, np.mean(times))  # total items = batch_size * threads
                standard_devs[threads] = np.std(times)
                
                print(f"{threads:2d} threads: {np.mean(times):8.2f} ms total, +-{np.std(times):6.2f} ms")
        
        return Results(self.rtt, self.rtt_std, results, standard_devs)
    
    async def run_serial_test(self, variable: List[int], num_iterations: int = 2, **kwargs) -> Results:
        """Run single-threaded batch size test"""
        print("Running single-threaded variable test...")
        results = {}
        standard_devs = {}
        
        connector = aiohttp.TCPConnector(ssl=None)
        async with aiohttp.ClientSession(connector=connector) as session:
            
            for var in variable:
                times = []

                for _ in range(num_iterations):
                    _, elapsed = await self.make_single_request(session, True, var=var, **kwargs)
                    times.append(elapsed)
                
                results[var] = (var, np.mean(times))
                standard_devs[var] = np.std(times)
                print(f"Variable value: {var:4d} | Mean Time: {np.mean(times):8.2f} ms")
        
        return Results(self.rtt, self.rtt_std, results, standard_devs)
    

    def plot_results(self, data: Results, xlabel: str, ylabel: str, title: str, filename: str):
        """Plot and save results"""
        data.plot(title, xlabel, ylabel, filename)

    @classmethod
    def add_common_args(cls, parser: argparse.ArgumentParser):
        """Add common CLI arguments"""
        parser.add_argument("--ip", required=True, help="SGX wallet IP address")
        parser.add_argument("--batch-sizes", dest="batch_sizes", 
                            help="Comma-separated batch sizes for serial test")
        parser.add_argument("--parallel-threads", dest="parallel_threads",
                            help="Comma-separated thread counts for parallel test")
        parser.add_argument("--iterations", type=int, 
                            help="Number of iterations per data point")
        parser.add_argument("--parallel-batch-size", dest="parallel_batch_size", type=int,
                            help="Fixed batch size per request in parallel test")

    @classmethod
    def add_test_args(cls, parser: argparse.ArgumentParser):
        """Override in subclass to add test-specific arguments"""
        pass

    @classmethod
    def create_parser(cls) -> argparse.ArgumentParser:
        """Create argument parser with common + test-specific args"""
        parser = argparse.ArgumentParser(description=f"{cls.name} Performance Test")
        cls.add_common_args(parser)
        cls.add_test_args(parser)
        return parser

    async def run(self):
        """Run the full test suite"""
        # Serial test
        results = await self.run_serial_test(self.batch_sizes, self.num_iterations)
        self.plot_results(results, self.xlabel, self.ylabel, 
                         f"{self.name} Performance Test", 
                         f"{self.name.lower()}-serial")

        # Parallel test
        results = await self.run_parallel_test(self.parallel_threads, self.parallel_batch_size, self.num_iterations)
        self.plot_results(results, "Number of Threads", "Throughput (ops/sec)",
                         f"{self.name} Performance Test (Parallel)",
                         f"{self.name.lower()}-parallel")

    @classmethod
    async def main(cls):
        """Entry point for running the test"""
        parser = cls.create_parser()
        args = parser.parse_args()
        test = await cls.create(args.ip, args)
        await test.run()
