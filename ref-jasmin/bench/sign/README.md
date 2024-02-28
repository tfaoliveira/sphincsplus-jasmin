# Benchmarks


> echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
> make clean && make all -j8 && make run && ./run-bench.py

<br>

`make all -j8`: Compiles the executables to run benchmarks and generates the object files 
`(make all -j8  383,87s user 2,82s system 513% cpu 1:15,27 total)`

`./run-bench.py`: Prints results about the benchmarks to stdout