#!/bin/bash

cargo build --bin Task3

EXECUTABLE="./target/debug/Task3"
LOG_FILE="./dev-resources/Task3/http.log"
$EXECUTABLE --file "$LOG_FILE"