# clean all build files
rm -rf *.o
rm -rf .deps/*.Po
rm -rf secure_enclave/*.o
rm -rf secure_enclave/.deps/*.Po
rm -rf Makefile Makefile.in
rm -rf secure_enclave/Makefile

if [ "$1" = "--full" ]; then
  git submodule update --init --recursive --force
  git submodule foreach --recursive 'git reset --hard && git clean -xfd'
fi