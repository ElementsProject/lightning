#! /bin/bash
cd lnprototest || exit
for i in range{0..20};
do
  if make check PYTEST_ARGS='--runner=lnprototest.clightning.Runner -n4 --dist=loadfile --log-cli-level=DEBUG'; then
    echo "iteration $i succeeded"
  else
    echo "iteration $i failed"
    exit 1
  fi
done
