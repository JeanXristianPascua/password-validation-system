#################################################
# Password Validation System
# CPSC 3615 - Jean Pascua
#
# Features:
# - Reads a password from the user
# - Checks password strength (length + classes)
# - Encodes password with XOR
# - Compares against stored encoded password
# - Limits user to 3 failed attempts, then locks
#################################################

.data
# ------------------------------------------------
# Requirements / Constants
# ------------------------------------------------
min_len:        .word 8          # minimum password length
xor_key:        .word 0x5A       # simple XOR key for encoding

# stored password = "Cs3615!1" encoded with XOR key 0x5A
#   C    s    3    6    1    5    !    1
# 0x19 0x29 0x69 0x6C 0x6B 0x6F 0x7B 0x6B
stored_pwd:     .byte 0x19,0x29,0x69,0x6C,0x6B,0x6F,0x7B,0x6B,0x00

# ------------------------------------------------
# User-facing Messages
# ------------------------------------------------
weak_msg:       .asciiz "Weak password.\n"
deny_msg:       .asciiz "Access Denied.\n"
success_msg:    .asciiz "Login Successful.\n"
locked_msg:     .asciiz "Too many attempts. System locked.\n"
prompt_msg:     .asciiz "Enter your password: "

# ------------------------------------------------
# Buffers
# ------------------------------------------------
input_buffer:   .space 32        # up to 31 chars + null terminator


#################################################
# CODE SECTION
#################################################
.text
.globl main

#################################################
# main
# - Loops login attempts (max 3)
# - For each attempt:
#     * prompts user
#     * reads password
#     * checks strength
#     * encodes strong passwords
#     * compares to stored encoded password
# - Locks system after 3 failures
#################################################
main:
    li  $s0, 0               # $s0 = failed attempt counter = 0

login_loop:
    # if failed attempts >= 3 -> lock system
    bge $s0, 3, locked

    # ---- prompt user ----
    li  $v0, 4
    la  $a0, prompt_msg
    syscall

    # ---- read password into buffer ----
    li  $v0, 8
    la  $a0, input_buffer
    li  $a1, 32
    syscall

    # ---- check strength ----
    la  $a0, input_buffer
    jal check_strength            # v0 = 1 strong, 0 weak

    beq $v0, $zero, weak_path     # if weak, handle weak case

    # ---- strong password: encode it ----
    la  $a0, input_buffer
    jal encode_password

    # ---- compare encoded input with stored encoded password ----
    la  $a0, input_buffer         # encoded user input
    la  $a1, stored_pwd           # stored encoded password
    jal compare_strings           # v0 = 1 if equal, 0 if not

    beq $v0, 1, login_success     # if match -> success

    # ---- strong but incorrect password ----
    li  $v0, 4
    la  $a0, deny_msg
    syscall

    addi $s0, $s0, 1              # failed_attempts++
    j   login_loop


weak_path:
    # weak password case
    li  $v0, 4
    la  $a0, weak_msg
    syscall

    addi $s0, $s0, 1              # failed_attempts++
    j   login_loop


login_success:
    li  $v0, 4
    la  $a0, success_msg
    syscall
    j   end_program


locked:
    li  $v0, 4
    la  $a0, locked_msg
    syscall
    j   end_program


end_program:
    li  $v0, 10
    syscall


#################################################
# check_strength
# INPUT : $a0 = address of input_buffer
# OUTPUT: $v0 = 1 (strong), 0 (weak)
#
# Rules:
# - length >= min_len
# - at least one uppercase letter
# - at least one lowercase letter
# - at least one digit
# - at least one special character
#################################################
check_strength:
    li  $t1, 0       # uppercase flag
    li  $t2, 0       # lowercase flag
    li  $t3, 0       # digit flag
    li  $t4, 0       # special flag
    li  $t5, 0       # length counter

    move $t0, $a0    # $t0 points to current character

loop_chars:
    lb  $t6, 0($t0)
    beq $t6, 0, done           # stop at null terminator

    # also stop at newline so it doesn't count as special/length
    li  $t9, 10                # '\n'
    beq $t6, $t9, done

    # ----- uppercase? -----
    li  $t7, 'A'
    blt $t6, $t7, check_lower
    li  $t7, 'Z'
    bgt $t6, $t7, check_lower
    li  $t1, 1                 # found uppercase
    j   next_char

check_lower:
    # ----- lowercase? -----
    li  $t7, 'a'
    blt $t6, $t7, check_digit
    li  $t7, 'z'
    bgt $t6, $t7, check_digit
    li  $t2, 1                 # found lowercase
    j   next_char

check_digit:
    # ----- digit? -----
    li  $t7, '0'
    blt $t6, $t7, check_special
    li  $t7, '9'
    bgt $t6, $t7, check_special
    li  $t3, 1                 # found digit
    j   next_char

check_special:
    # anything that is not A–Z, a–z, or 0–9 is treated as special
    li  $t4, 1                 # found special

next_char:
    addi $t5, $t5, 1           # length++
    addi $t0, $t0, 1           # move to next char
    j    loop_chars

done:
    # check minimum length
    lw  $t7, min_len
    blt $t5, $t7, fail

    # require all 4 flags: uppercase, lowercase, digit, special
    and $t8, $t1, $t2
    and $t8, $t8, $t3
    and $t8, $t8, $t4
    beq $t8, 1, strong

fail:
    li  $v0, 0                 # weak
    jr  $ra

strong:
    li  $v0, 1                 # strong
    jr  $ra


#################################################
# encode_password
# INPUT : $a0 = address of buffer to encode
# EFFECT: XOR-encodes chars in-place until '\n' or '\0'
#################################################
encode_password:
    # load XOR key into $t2
    la  $t1, xor_key
    lw  $t2, 0($t1)

    move $t0, $a0              # pointer into string

enc_loop:
    lb  $t3, 0($t0)
    beq $t3, 0, enc_done       # stop at existing null

    li  $t4, 10                # newline '\n'
    beq $t3, $t4, make_null    # turn newline into null and stop

    xor $t3, $t3, $t2          # XOR character with key
    sb  $t3, 0($t0)            # store back encoded byte

    addi $t0, $t0, 1           # move to next char
    j    enc_loop

make_null:
    sb  $zero, 0($t0)          # replace newline with '\0'
    j   enc_done

enc_done:
    jr  $ra


#################################################
# compare_strings
# INPUT : $a0 = addr of first string
#         $a1 = addr of second string
# OUTPUT: $v0 = 1 (equal), 0 (not equal)
#################################################
compare_strings:
    move $t0, $a0      # ptr1
    move $t1, $a1      # ptr2

cmp_loop:
    lb  $t2, 0($t0)
    lb  $t3, 0($t1)

    bne $t2, $t3, cmp_not_equal   # bytes differ → not equal
    beq $t2, 0, cmp_equal         # both zero → equal

    addi $t0, $t0, 1
    addi $t1, $t1, 1
    j    cmp_loop

cmp_not_equal:
    li  $v0, 0
    jr  $ra

cmp_equal:
    li  $v0, 1
    jr  $ra
