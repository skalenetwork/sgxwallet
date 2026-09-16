#!/usr/bin/env python3

import subprocess
from pathlib import Path

topDir = Path(__file__).resolve().parent.parent
print(topDir)

cpp_extensions = (".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".ipp")
src_dirs = (
    (topDir, False),
    (topDir / "zmq_src", False),
    (topDir / "secure_enclave", False),
    (topDir / "tests", True),
)

for directory, recursive in src_dirs:
    print(directory)
    files = directory.rglob("*") if recursive else directory.iterdir()
    for file in files:
        if file.is_file() and file.suffix in cpp_extensions:
            print(file)
            subprocess.run(
                ["clang-format-14", "-i", "-style=file", str(file)], check=True
            )
