#!/bin/bash

# Check if argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <size>"
    echo "  size: The number of bytes to include in the contract constructor"
    exit 1
fi

# Get the size from the argument
N=$1

# Make sure src directory exists
mkdir -p src

# Create the contract file with header
cat > src/LargeContract.sol << EOF
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LargeContract {
    constructor() {
        bytes memory data = hex"
EOF

# Append hex data without newlines (critical!)
# Using echo -n to avoid line breaks
for ((i=0; i<$N; i++)); do
    echo -n "ff" >> src/LargeContract.sol
done

# Complete the contract
cat >> src/LargeContract.sol << EOF
";
        assembly {
            pop(mload(data))
        }
    }
}
EOF

echo "Contract generated at src/LargeContract.sol with $N bytes of data"