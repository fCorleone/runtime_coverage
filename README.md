How to use this library:
1) cargo build this library
The change dir to the project
2) cp ../coverage_rust/target/debug/libcoverage_rust.so /usr/local/lib/
3) cargo clean
4) RUSTFLAGS="-Clink-dead-code -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-trace-pc-guard  -C llvm-args=-sanitizer-coverage-level=2  -Cdebug-assertions -C codegen-units=1  -C link-arg=-lcoverage_rust"  cargo build
5) run your binary.

-Clink-dead-code -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-trace-pc-guard  -C llvm-args=-sanitizer-coverage-level=2  -Cdebug-assertions -C codegen-units=1  -C link-arg=-lcoverage_rust