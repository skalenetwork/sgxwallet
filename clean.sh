# clean all build files
rm -rf *.o
rm -rf .deps/*.Po
rm -rf .dirstamp
rm -rf zmq_src/*.o
rm -rf zmq_src/.deps/*.Po
rm -rf zmq_src/.dirstamp
rm -rf third_party/intel/*.o
rm -rf third_party/intel/.deps/*.Po
rm -rf third_party/intel/.dirstamp
rm -rf secure_enclave/*.o
rm -rf secure_enclave/.deps/*.Po
rm -rf Makefile Makefile.in
rm -rf secure_enclave/Makefile

rm ./*.m4

# Remove all generated files in all submodules
if [ "$1" = "--full" ]; then
  git submodule update --init --recursive --force
  git submodule foreach --recursive 'git reset --hard && git clean -xfd'
fi
