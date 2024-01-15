# Benchmarks

This assumes that the jasmin files were already compiled to assembly and are
in the respective folder (e.g. `ref-jasmin/test/sign/bin`) (TODO: Fix this)

```sh
cd ../ref-jasmin/test/sign && make -j8
cd - && make 
make run
```