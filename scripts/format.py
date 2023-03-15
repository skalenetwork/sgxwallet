#!/usr/bin/env python3

import os
import subprocess

os.chdir("..")
topDir = os.getcwd()
print(topDir)

cpp_extensions = (".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".ipp")
src_dirs = (topDir, topDir + "/zmq_src", topDir + "/secure_enclave")

for directory in src_dirs:
    print(directory)
    for file in os.listdir(directory):
            if os.path.isfile(os.path.join(directory,file)) and file.endswith(cpp_extensions):
                print(file)
                if file != "catch.hpp":
                    os.system("clang-format-14 -i -style=file " + directory + "/" + file)
