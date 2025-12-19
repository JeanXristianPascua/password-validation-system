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
