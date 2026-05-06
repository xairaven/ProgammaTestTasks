#!/bin/bash

cargo build --bin Task3

EXECUTABLE="./target/debug/Task3"
JOURNAL_FILE="./dev-resources/Task3/http.log"
$EXECUTABLE --file "$JOURNAL_FILE" --log-level info