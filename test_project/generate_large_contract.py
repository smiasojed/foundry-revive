#!/usr/bin/env python3

import sys
import os

def generate_large_init_contract(n):
    """
    Generates a string containing the code of a Solidity contract.
    
    This contract compiles to a large init bytecode size, but small runtime size.
    """
    # Create a sequence of n bytes, all set to 0xff
    data = b'\xff' * n
    
    # Convert to hex string (equivalent to alloy_primitives::hex::encode)
    hex_string = data.hex()
    
    # Format the contract exactly as in the Rust function
    return f"""contract LargeContract {{
    constructor() {{
        bytes memory data = hex"{hex_string}";
        assembly {{
            pop(mload(data))
        }}
    }}
}}    
"""

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <size>")
        print("  size: The number of bytes to include in the contract constructor")
        sys.exit(1)
    
    try:
        n = int(sys.argv[1])
    except ValueError:
        print(f"Error: Size must be an integer")
        sys.exit(1)
    
    # Create src directory if it doesn't exist
    os.makedirs("src", exist_ok=True)
    
    # Generate contract and write to file
    contract = generate_large_init_contract(n)
    
    with open("src/LargeContract.sol", "w") as f:
        # Add SPDX license and pragma
        f.write("// SPDX-License-Identifier: MIT\n")
        f.write("pragma solidity ^0.8.0;\n\n")
        f.write(contract)
    
    print(f"Contract generated at src/LargeContract.sol with {n} bytes of data")