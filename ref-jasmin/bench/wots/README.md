# Benchmarks


> echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
> make clean && make all -j8 && make run && ./run-bench.py

<br>

`make all -j8`: Compiles the executables to run benchmarks and generates the object files 
`()`

`./run-bench.py`: Prints results about the benchmarks to stdout