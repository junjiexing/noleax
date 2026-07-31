; Deterministic register workload for the thread-hijack context-restore test.
;
; uint64_t noleax_register_workload(uint64_t seed, uint32_t iterations,
;                                   uint32_t* error_flag)
;
; Loads distinctive sentinels into the non-volatile GPRs (rbx, rbp, rdi, rsi,
; r15) and XMM6-XMM15, then verifies them on every loop iteration while
; accumulating a deterministic floating-point value in volatile registers. If
; anything (for example a botched thread-hijack context restore) clobbers a
; non-volatile register, error_flag is set to 1. The return value folds the
; accumulator into a 64-bit digest input.

.code

noleax_register_workload proc
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 0A8h                       ; xmm save area, keeps rsp 16-aligned

    movdqu  [rsp+00h], xmm6
    movdqu  [rsp+10h], xmm7
    movdqu  [rsp+20h], xmm8
    movdqu  [rsp+30h], xmm9
    movdqu  [rsp+40h], xmm10
    movdqu  [rsp+50h], xmm11
    movdqu  [rsp+60h], xmm12
    movdqu  [rsp+70h], xmm13
    movdqu  [rsp+80h], xmm14
    movdqu  [rsp+90h], xmm15

    ; rcx = seed, edx = iterations, r8 = error flag
    mov     r12, rcx
    mov     r13d, edx
    mov     r14, r8

    ; Non-volatile GPR sentinels.
    mov     rbx, 0123456789ABCDEFh
    mov     rbp, 0FEDCBA9876543210h
    mov     rdi, 0A5A5A5A5A5A5A5A5h
    mov     rsi, 05A5A5A5A5A5A5A5Ah
    mov     r15, 0DEADBEEFCAFEBABEh

    ; Non-volatile XMM sentinels (both lanes identical).
    mov     rax, 01122334455667788h
    movq    xmm6, rax
    punpcklqdq xmm6, xmm6
    mov     rax, 02233445566778899h
    movq    xmm7, rax
    punpcklqdq xmm7, xmm7
    mov     rax, 033445566778899AAh
    movq    xmm8, rax
    punpcklqdq xmm8, xmm8
    mov     rax, 0445566778899AABBh
    movq    xmm9, rax
    punpcklqdq xmm9, xmm9
    mov     rax, 05566778899AABBCCh
    movq    xmm10, rax
    punpcklqdq xmm10, xmm10
    mov     rax, 066778899AABBCCDDh
    movq    xmm11, rax
    punpcklqdq xmm11, xmm11
    mov     rax, 0778899AABBCCDDEEh
    movq    xmm12, rax
    punpcklqdq xmm12, xmm12
    mov     rax, 08899AABBCCDDEEFFh
    movq    xmm13, rax
    punpcklqdq xmm13, xmm13
    mov     rax, 099AABBCCDDEEFF00h
    movq    xmm14, rax
    punpcklqdq xmm14, xmm14
    mov     rax, 0AABBCCDDEEFF0011h
    movq    xmm15, rax
    punpcklqdq xmm15, xmm15

    ; Deterministic accumulator: xmm1 = sum, xmm2 = seed as double.
    pxor    xmm1, xmm1
    cvtsi2sd xmm2, r12

workloop:
    ; Verify GPR sentinels.
    mov     rax, 0123456789ABCDEFh
    cmp     rbx, rax
    jne     register_error
    mov     rax, 0FEDCBA9876543210h
    cmp     rbp, rax
    jne     register_error
    mov     rax, 0A5A5A5A5A5A5A5A5h
    cmp     rdi, rax
    jne     register_error
    mov     rax, 05A5A5A5A5A5A5A5Ah
    cmp     rsi, rax
    jne     register_error
    mov     rax, 0DEADBEEFCAFEBABEh
    cmp     r15, rax
    jne     register_error
    ; Verify XMM sentinels (low lane is enough: punpcklqdq mirrored them).
    movq    rax, xmm6
    mov     rdx, 01122334455667788h
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm7
    mov     rdx, 02233445566778899h
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm8
    mov     rdx, 033445566778899AAh
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm9
    mov     rdx, 0445566778899AABBh
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm10
    mov     rdx, 05566778899AABBCCh
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm11
    mov     rdx, 066778899AABBCCDDh
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm12
    mov     rdx, 0778899AABBCCDDEEh
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm13
    mov     rdx, 08899AABBCCDDEEFFh
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm14
    mov     rdx, 099AABBCCDDEEFF00h
    cmp     rax, rdx
    jne     register_error
    movq    rax, xmm15
    mov     rdx, 0AABBCCDDEEFF0011h
    cmp     rax, rdx
    jne     register_error

    ; Deterministic FP accumulation in volatile registers only.
    cvtsi2sd xmm0, r13d
    mulsd   xmm0, xmm2
    addsd   xmm1, xmm0
    addsd   xmm1, xmm2

    dec     r13d
    jnz     workloop

finish:
    ; Fold the accumulator into a 64-bit value.
    movq    rax, xmm1
    movq    rdx, xmm0
    xor     rax, rdx
    rol     rax, 17
    add     rax, r12

    movdqu  xmm6, [rsp+00h]
    movdqu  xmm7, [rsp+10h]
    movdqu  xmm8, [rsp+20h]
    movdqu  xmm9, [rsp+30h]
    movdqu  xmm10, [rsp+40h]
    movdqu  xmm11, [rsp+50h]
    movdqu  xmm12, [rsp+60h]
    movdqu  xmm13, [rsp+70h]
    movdqu  xmm14, [rsp+80h]
    movdqu  xmm15, [rsp+90h]
    add     rsp, 0A8h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

register_error:
    test    r14, r14
    jz      short finish
    mov     dword ptr [r14], 1
    jmp     short finish

noleax_register_workload endp
end
