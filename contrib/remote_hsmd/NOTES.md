

    ALT_SUBDAEMON='lightning_hsmd:remote_hsmd' \
    make VALGRIND=0 pytest \
    |& tee log
