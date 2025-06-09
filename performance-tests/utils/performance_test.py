import time
import asyncio
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

        print(times_list)
        print(num_reqsts_sent)
        print(rtt, rtt_std)

        times_without_rtt = times_list - rtt
        print(f"{'times without RTT':<30} {times_without_rtt}")
        # 1000 -> convert from ms to seconds        
        self.y_vals = num_reqsts_sent / (times_without_rtt / 1000)
        print(f"{'throughput mean:':<30} {self.y_vals}")

        y_std = np.array(list(std.values()))
        print(f"{'std:':<30} {y_std}")

        self.upper_bound = np.maximum(num_reqsts_sent / ((times_without_rtt + y_std) / 1000), 0)
        self.lower_bound = np.maximum(num_reqsts_sent / ((times_without_rtt - y_std) / 1000), 0)
        print(f"{'upper bound:':<30} {self.upper_bound}")
        print(f"{'lower bound:':<30} {self.lower_bound}")

        self.rtt_upper_bound_upper_std = np.maximum(num_reqsts_sent / ((times_without_rtt + y_std + rtt_std) / 1000), 0)
        self.rtt_upper_bound_lower_std = np.maximum(num_reqsts_sent / ((times_without_rtt + y_std - rtt_std) / 1000), 0)
        print(f"{'RTT upper bound upper std:':<30} {self.rtt_upper_bound_upper_std}")
        print(f"{'RTT upper bound lower std:':<30} {self.rtt_upper_bound_lower_std}")

        self.rtt_lower_bound_upper_std = np.maximum(num_reqsts_sent / ((times_without_rtt - y_std + rtt_std) / 1000), 0)
        self.rtt_lower_bound_lower_std = np.maximum(num_reqsts_sent / ((times_without_rtt - y_std - rtt_std) / 1000), 0)
        print(f"{'RTT lower bound upper std:':<30} {self.rtt_lower_bound_upper_std}")
        print(f"{'RTT lower bound lower std:':<30} {self.rtt_lower_bound_lower_std}")

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
    
    def __init__(self, ip: str):
        self.endpoint = "http://" + ip + ":1029"

        # Initialized on 'create' method
        self.keys = None
        self.rtt = None
        self.rtt_std = None

    @classmethod
    async def create(cls, ip: str):
        """Async factory method to create and initialize the test"""
        instance = cls(ip)
        await instance.initialize()
        return instance
    
    async def initialize(self):
        """Initialize async components like RTT measurement"""
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
    def create_payload(self, **kwargs) -> Dict[str, Any]:
        """Create the JSON-RPC payload for this test"""
        pass

    @abstractmethod
    def get_method_name(self) -> str:
        """Get JSON-RPC method name for this test"""
        pass
    
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
    
    # Returns a tuple ( results, standard deviation )
    async def run_parallel_test(self, num_threads: List[int], variable: int, num_iterations: int = 2, **kwargs) -> Results:
        """Run parallel throughput test with different thread counts"""
        print("Running parallel throughput test...")
        results = {}
        standard_devs = {}
        
        connector = aiohttp.TCPConnector(ssl=None)
        async with aiohttp.ClientSession(connector=connector) as session:
            
            for threads in num_threads:
                times = []
                for _ in range(num_iterations):
                    start_time = time.perf_counter()
                    # Create N parallel tasks
                    tasks = [self.make_single_request(session, True, var = variable, **kwargs) for _ in range(threads)]
                    await asyncio.gather(*tasks)
                    total_time = (time.perf_counter() - start_time)
                    times.append(total_time)
                
                results[threads] = (variable, np.mean(times))
                standard_devs[threads] = np.std(times)
                
                print(f"{threads:2d} threads: {np.mean(times):8.2f} ms total, +-{np.std(times):6.2f} ms")
        
        return Results(self.rtt, self.rtt_std, results, standard_devs, variable)
    
    # Returns a tuple ( results, standard deviation )
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