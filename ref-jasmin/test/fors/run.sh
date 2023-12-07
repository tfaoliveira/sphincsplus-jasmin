#!/usr/bin/bash

make clean; make -j8 default; time make -j8 run
