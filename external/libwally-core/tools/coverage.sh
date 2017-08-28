#/bin/bash

# Helper to generate coverage reports.
# ./tools/coverage.sh clean : Sets coverage stats to 0.
# ./tools/coverage.sh       : Calculates coverage stats, produces
#                             src/lcov/index.html as output.

lcov="lcov --directory=src/ --base-directory src/"

if [ $1 = "clean" ]; then
    $lcov --zerocounters
    $lcov --output-file src/lcov_base --capture --initial
else
    $lcov --output-file src/lcov_result --capture --ignore-errors=gcov
    $lcov --output-file src/lcov_total --add-tracefile src/lcov_base --add-tracefile src/lcov_result --ignore-errors=gcov
    genhtml --demangle-cpp -o src/lcov/ src/lcov_total
fi
