# clean all build files
rm -rf *.o
rm -rf .deps/*.Po
rm -rf secure_enclave/*.o
rm -rf secure_enclave/.deps/*.Po
rm -rf Makefile Makefile.in
rm -rf secure_enclave/Makefile

# Remove all libtool generated files
# TODO - remove this
rm -f ltmain.sh libtool
rm -f m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
find . -name '.libs' -type d -prune -exec rm -rf {} +
find . -name '*.la' -o -name '*.lo' | xargs -r rm -f

rm ./*.m4

# Remove all generated files in all submodules
if [ "$1" = "--full" ]; then
  git submodule update --init --recursive --force
  git submodule foreach --recursive 'git reset --hard && git clean -xfd'
fi