# Password Validation System (MIPS Assembly)

**Author:** Jean Pascua  

## Overview
This project implements a password validation system in MIPS assembly language.  
It enforces password strength rules, encodes passwords using XOR, and validates
user login attempts against a stored encoded password.

## Features
- Minimum password length requirement
- Requires:
  - Uppercase letter
  - Lowercase letter
  - Digit
  - Special character
- XOR-based password encoding
- Secure password comparison
- Maximum of 3 failed login attempts before lockout

## Files
- `pasword-validation-system.asm` — Main MIPS assembly source code

## How to Run
1. Open the file in **MARS** or **QtSPIM**
2. Assemble and run
3. Enter passwords when prompted

## Notes
- Stored password is XOR-encoded for basic security
- Newline input is handled correctly
- System locks after 3 failed attempts
