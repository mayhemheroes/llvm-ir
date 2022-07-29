# Build Stage
FROM ghcr.io/evanrichter/llvm-asan:13.0.1 as builder

## Add source code to the build stage.
ADD . /src
WORKDIR /src
RUN cd fuzz && env LLVM_SYS_130_PREFIX=/opt/llvm/ cargo fuzz build

# Package Stage
FROM rustlang/rust:nightly

COPY --from=builder /src/fuzz/target/x86_64-unknown-linux-gnu/release/parse_bc /
RUN mkdir /testsuite
ADD tests/basic_bc/llvm13/* /testsuite/
