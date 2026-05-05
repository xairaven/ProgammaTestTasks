#!/bin/bash

cargo build --release --bin Task1
if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi
../target/release/Task1