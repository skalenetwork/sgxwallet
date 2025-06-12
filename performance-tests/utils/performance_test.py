import time
import asyncio
import aiohttp
import ssl
import matplotlib.pyplot as plt
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from utils.sgx_key_utils import provision_keys


class PerformanceTest(ABC):
    """Base class for performance tests"""
    
    def __init__(self, ip: str):
        self.endpoint = "https://" + ip + ":1026"
        self.cert_path = "."

        # Initialized on 'create' method
        self.ssl_context = None
        self.keys = None
        self.rtt = None

    @classmethod
    async def create(cls, ip: str):
        """Async factory method to create and initialize the test"""
        instance = cls(ip)
        await instance.initialize()
        return instance
    
    async def initialize(self):
        """Initialize async components like RTT measurement"""
        self.ssl_context = self._create_ssl_context()

        if self.rtt is None:
            self.rtt = await self._measure_rtt()

        print("Generating keys...")
        self.keys = provision_keys(self.endpoint, self.cert_path)
    
    def _create_ssl_context(self):
        """Create SSL context with client certificates"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.load_cert_chain(f"{self.cert_path}/sgx.crt", f"{self.cert_path}/sgx.key")
        return ssl_context
    
    async def _measure_rtt(self, num_samples: int = 10) -> float:
        """Measure round-trip time with invalid requests"""
        print("Measuring RTT...")
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context)  
        async with aiohttp.ClientSession(connector = connector) as session:
            times = []
            for _ in range(num_samples):
                # Send invalid request to measure RTT
                _, elapsed = await self.make_single_request(session, False)
                times.append(elapsed)
        
        avg_rtt = sum(times) / len(times)
        print(f"Average RTT: {avg_rtt:.2f} ms")
        return avg_rtt
    
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
    
    async def run_parallel_test(self, num_threads: List[int], variable: int, **kwargs) -> Dict[int, float]:
        """Run parallel throughput test with different thread counts"""
        print("Running parallel throughput test...")
        results = {}
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            
            for threads in num_threads:
                start_time = time.perf_counter()
                
                # Create N parallel tasks
                tasks = [self.make_single_request(session, True, var = variable, **kwargs) for _ in range(threads)]
                await asyncio.gather(*tasks)
                
                total_time = (time.perf_counter() - start_time) * 1000 - self.rtt
                throughput = (threads * variable) / (total_time / 1000)  # requests per second
                
                results[threads] = throughput
                print(f"{threads:2d} threads: {total_time:8.2f} ms total, {throughput:6.2f} req/s")
        
        return results
    
    async def run_serial_test(self, variable: List[int], num_iterations: int = 2, **kwargs) -> Dict[int, float]:
        """Run single-threaded batch size test"""
        print("Running single-threaded variable test...")
        results = {}
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            
            for var in variable:
                total_time = 0
                
                for _ in range(num_iterations):
                    _, elapsed = await self.make_single_request(session, True, var=var, **kwargs)
                    total_time += elapsed - self.rtt # Subtract RTT overhead
                
                avg_time = total_time / num_iterations
                results[var] = avg_time
                print(f"Variable value: {var:4d} | Mean Time: {avg_time:8.2f} ms")
        
        return results
    
    def plot_results(self, data: Dict[int, float], xlabel: str, ylabel: str, title: str, filename: str):
        """Plot and save results"""
        x_vals = list(data.keys())
        y_vals = list(data.values())
        
        plt.figure(figsize=(10, 6))
        plt.plot(x_vals, y_vals, marker='o')
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.title(title)
        plt.grid(True)
        plt.savefig(f"./plots/{filename}.png")
        plt.show()