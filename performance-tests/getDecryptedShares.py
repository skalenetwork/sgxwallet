import asyncio
from typing import Any, Dict
import argparse
from utils.performance_test import PerformanceTest

#########################################################
#              Performance Test
#########################################################

class DecryptSharesTest(PerformanceTest):
    def __init__(self, ip: str):
        super().__init__(ip)

        self.rand_shares = [
            "1817360b33133685ae40c1bd001de2daab87e06b388ab09a71e06b4c6886395c0e17398de1a799e1cbe4772de459c562db259dd31d7c75ec91af03f65f7103a02fd829a75145e166b5d814fe79244d04a72fe042be34061fb1a76a069487f52c1f6816e50e7f703495d716a442d8897cd315b956b289e3f42244ce6943825c60",
            "2a9f1e01a3d90d87011b4ec3a79d69b6f02491bb02a3256df29d58d551ee85a12ce93edab079c1c6cf5b7d9c37e1972fdb45c52a227afc6f9643621b07192b54027952562e8efa885fef1d35648261a1ca8c82ae7a09401e2d1788e865993ce61697e37b3abe4fab09ea7100debe592907a81ff0f66ac92b0a049ce6b3f818d7",
            "1a7a60693250bff4f8a5653c92865ecc77b27f827d0bdd77618b60f61f21e2d0108bee85c27429fe643485bd35f8da5bba715ba9be0157b593e7a02b89e5dc720ddf5654a0b51ac052c6122cbbc49835f1de99d4faea998726a986626cafb6c502ffb6343f69e7568e921abd15d37b554cd297d63db8eea6eb044baf1c51a261",
            "234145ccf8bfc1a9a586886be5662723d3c418396546879798358d4782df28e725b31995d66f66ac61591ba5308071506fa54154a387600c3c396dd1b72fdb071deada3f165be8a4c87cb8185af93f54b115d018ea7601c965ca8a68d3d1e38504e1c2b17e278cf6e4ede06ce702515294fe4c0467da2e36e6720f8eefa5779f",
            "239b73262b509e5f5c5a6a0d64b659b7fbbae760a2986414354254f82b28705108ed06581adc038bd61718c98fb148950ca195e3b178549510f436dfa719c12709bdfef1020fd2ced168ed8821a5855ed3e262523544883de209075f00cbf7082000f3ec6554769cd51dd077c78e551d0626acaaf42af61f96ec704afd4a5dad",
            "23af9f09115f209714ecc7aeb5ab1aaa73aadf3e60eb6736500d358e6f46536c0287fd3ffb32747fb196147dd2a7c2507a6269e44c75e28b66741adaafb7b3791901dc0a069d388b01dbf59c056c003df35a5cac973f82cb2903ed9262f5637e1815045c6401e1d4369ec2c11efc774dffa5078f46e46c86fa06c779e186861b",
            "1d9be5a7a95137db6750a1c6b13f99cf72fed46ce04c17ab1901bba88f7840122a40e6801d35b670fd9b1142b5dd9579a4398c2777596b8eee8a78103ea523ab2ad56b1a027c58ddf2cfde5b4301e4c805db30e434af9fd2216ed671deadea29050f19a31dc0d2b387cc82ee4adba3bc857ac26344ef74b1cdc58d48f9aee9c6",
            "2e34797010b477b214e4a9ed636033271532f29fb94577874beb603b320517490e6a0f47b81740502888fb332af5d994e282fae0f80dbcfa9d97ff3bec0b55760b0cb63904ad05f86f40585ae402de4b7c51d9a6741833f446349b5de0423a660e8e6d74e2db8494f5513d95617853bec6d70a4399059b1627feb098af0dd4cf",
            "25267453e6e1c415a11bd3f0ca13b67e14616c2dd9bad6e25dd55ba1c920ea462b64a40d3d59efd1914c7f5c3ebf6ed61485bf50fc8da48b5c961d3f56e52e5c00850ded4f60d730311b56842f5758797d657c72b794b9a88cd0e5c789cda57d25bfccde31dc9f5dbdaa0814b693ea7ba77c7d35fb8cdfcd2b126cf9647f37bd",
            "15de388dbad3806881d9a2dc1ce50e3b971aff142b4fa51bcf4851ed8fff9411020cc18e238561aab3b2115784bfd4b59058ce233ef0dea837fc1669e1f6b7260a8bfa21333a1d8e5bb51dec8b3ce99e622a88ef1c321f24e2502e57cd0d2c9d2af55d18c58e0ef78f9765565021087ccda10d6acc15ce8a357575d3e1e9a762",
            "0e10684ed15459415b858a9eec84fd3282e68a38c0b8c13cc47a53a6642a1f3625b249e92a635ec69ff7ebd0c8d0adee870d86a7f3df0f37a576440f21a51898115f3a1c5b035056b12f0e90e4b9e8b0967bcb9e2634f6aeb6cca271a74de9fb276583468323bd5f0687ac40171c0e8d768a60e597dc5fec9caab407fc1b736b",
            "243796792445b8523071eaa55b44d2295539504c98de9fd73b9c41217b7e1b32190a927dffc063bb2934b85108771dd1f5e95712a3e7e34caa9716129c5120a8083d2d725010c7635d052c08cab319f62caebd4fb389cc8828093cfa0e60883a2a2dfa8cc8257b4a64b09f3ad816cbfedccde02506b4d9278db84a713e9f21e8",
            "1167e1f5c133ec7f90856379036269cfbb4301088e845be781c9fca33d7147ce07e2568d1dd7d91792c57b81a5180f734148885651fc9bfba6d8e462ca46f6e306b773010b64df82f927d75780ba8a660ad450fd0a6a5cee3e0d0d7862b2b4d51a90e322711fefbf690fa062e983f301f02a82a1274d067c1c0d853444519ff7",
        ]

        self.num_batches_each = 50

        # single request data
        self.batch_sizes = [2, 4, 8, 16, 32, 64, 128]

        # parallel test data
        self.parallel_threads = [ 1, 2, 4, 8, 16]
        self.parallel_batch_size = 2000
    
    # Send by default batch of size 1000 - for parallel tests
    def create_payload(self, var: int = 1000, **kwargs) -> Dict[str, Any]:
        import random
        
        # For batch tests
        batch = [random.choice(self.rand_shares) for _ in range(var)]
        return {
            "blsKeyName": self.keys["bls"]["name"],
            "publicDecryptionValues": batch
        }
        
    def get_method_name(self) -> str:
        return "getDecryptionShares"

async def main(args):
    test = await DecryptSharesTest.create(args.ip)
    results = await test.run_serial_test(test.batch_sizes, test.num_batches_each)
    test.plot_results(results, "Batch size", "Time (ms)", "DecryptShares Performance Test", "getDecryptionShares-single-thread")

    # resutls = await test.run_parallel_test(test.parallel_threads, test.parallel_batch_size, test.num_batches_each)
    # test.plot_results(resutls, "Number of Threads", "Trhoughput", "DecryptShares Performance Test", "getDecryptionShares-parallel")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True, help="ip address")
    args = parser.parse_args()

    asyncio.run(main(args))

