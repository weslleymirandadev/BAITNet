; ipv69_send - monta frame Ethernet + header IPv69 e envia via AF_PACKET
; Uso: sudo ./ipv69_send <interface> [dest_hex] [payload]
;   dest_hex: hex 64-bit (padrao 2), payload: string (padrao "hello from ipv69")
; MAC de origem via SIOCGIFHWADDR

SYS_SOCKET   equ 41
SYS_SENDTO   equ 44
SYS_IOCTL    equ 16
SYS_WRITE    equ 1
SYS_EXIT     equ 60

AF_PACKET    equ 17
SOCK_RAW     equ 3

ETH_P_IPV69  equ 0x6969

SIOCGIFINDEX  equ 0x8933
SIOCGIFHWADDR equ 0x8927

STDOUT       equ 1

IPv69_OFF    equ 14

%include "header.asm"
%include "bigendian.asm"

section .bss
    frame resb 1514
    ifreq resb 40
    saddr resb 20

section .data
    ; template do header, montado em assemble-time com as macros BE
    ipv69_template:
        db 0x69                         ; versao 6 + traffic class 9
        db 0
        BE16 0                          ; payload_len (preenchido em runtime)
        BE16 1
        db IPV69_NEXT_DGRAM
        db 64
        db IPV69_FLAG_NOFRAG
        db 0
        BE16 0
        BE32 1
        BE64 1
        BE64 2                          ; dest (sobrescrito em runtime)
    ipv69_template_len equ $ - ipv69_template

    payload_default db "hello from ipv69"
    payload_default_len equ $ - payload_default

    usage db "Usage: sudo ./ipv69_send <interface> [dest_hex] [payload]", 0xA
    usage_len equ $ - usage

section .text
global _start

_start:
    mov rax, [rsp]
    cmp rax, 2
    jl .usage

    mov rax, SYS_SOCKET
    mov rdi, AF_PACKET
    mov rsi, SOCK_RAW
    mov rdx, ETH_P_IPV69
    syscall
    test rax, rax
    js .exit
    mov r12, rax

    mov rdi, [rsp + 16]
    lea rsi, [rel ifreq]
.copy_name:
    mov al, [rdi]
    mov [rsi], al
    inc rdi
    inc rsi
    test al, al
    jnz .copy_name

    mov rax, SYS_IOCTL
    mov rdi, r12
    mov rsi, SIOCGIFINDEX
    lea rdx, [rel ifreq]
    syscall
    test rax, rax
    js .exit
    mov eax, [ifreq + 16]
    mov [saddr + 4], eax

    mov rax, SYS_IOCTL
    mov rdi, r12
    mov rsi, SIOCGIFHWADDR
    lea rdx, [rel ifreq]
    syscall
    test rax, rax
    js .exit

    ; sockaddr_ll: family, protocol, ifindex(+4), hatype(+8), halen(+11), addr(+12)
    mov word [saddr], AF_PACKET
    mov word [saddr + 2], ETH_P_IPV69
    mov word [saddr + 8], 1
    mov byte [saddr + 11], 6
    mov rax, 0xFFFFFFFFFFFF
    mov [saddr + 12], rax               ; broadcast

    ; dst MAC: broadcast (bytes 6-7 viram src MAC)
    mov rax, 0xFFFFFFFFFFFF
    mov [frame], rax

    ; src MAC: ifreq + 18 (sa_data do ifr_hwaddr)
    lea rsi, [rel ifreq + 18]
    lea rdi, [rel frame + 6]
    mov ecx, 6
.copy_mac:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .copy_mac

    mov word [frame + 12], ETH_P_IPV69

    ; payload: argv[3] ou default
    mov r13, payload_default
    mov r14, payload_default_len
    cmp qword [rsp], 4
    jl .have_payload
    mov r13, [rsp + 32]
    xor r14, r14
.len_payload:
    cmp byte [r13 + r14], 0
    je .have_payload
    inc r14
    cmp r14, 1400
    jae .have_payload
    jmp .len_payload
.have_payload:

    ; dest: argv[2] em hex ou 2
    mov r15, 2
    cmp qword [rsp], 3
    jl .have_dest
    mov rdi, [rsp + 24]
    call parse_hex
    mov r15, rax
.have_dest:

    lea rsi, [rel ipv69_template]
    lea rdi, [rel frame + IPv69_OFF]
    mov ecx, IPV69_HEADER_LEN
    rep movsb

    ; payload_len = 4 (portas) + dados
    lea eax, [r14 + 4]
    xchg al, ah
    mov [frame + IPv69_OFF + IPv69_Header.payload_len], ax

    ; dest BE64
    lea rdi, [rel frame + IPv69_OFF + IPv69_Header.dest + 7]
    mov rcx, 8
    mov rax, r15
.be64:
    mov [rdi], al
    shr rax, 8
    dec rdi
    dec rcx
    jnz .be64

    ; datagrama 253: src_port=1, dst_port=1, depois os dados
    mov byte [frame + IPv69_OFF + IPV69_HEADER_LEN], 0
    mov byte [frame + IPv69_OFF + IPV69_HEADER_LEN + 1], 1
    mov byte [frame + IPv69_OFF + IPV69_HEADER_LEN + 2], 0
    mov byte [frame + IPv69_OFF + IPV69_HEADER_LEN + 3], 1

    lea rdi, [rel frame + IPv69_OFF + IPV69_HEADER_LEN + 4]
    mov rsi, r13
    mov rcx, r14
    rep movsb

    ; padding ate 60 bytes (minimo do frame ethernet)
    lea rax, [rel frame + IPv69_OFF + IPV69_HEADER_LEN + 4]
    add rax, r14
    lea rbx, [rel frame + 60]
    cmp rax, rbx
    jae .no_pad
.pad:
    mov byte [rax], 0
    inc rax
    cmp rax, rbx
    jb .pad
.no_pad:

    lea rcx, [rel frame]
    sub rax, rcx
    mov rdx, rax

    mov rax, SYS_SENDTO
    mov rdi, r12
    lea rsi, [rel frame]
    xor r10, r10
    lea r8, [rel saddr]
    mov r9, 20
    syscall
    test rax, rax
    js .exit

.exit:
    mov rax, SYS_EXIT
    mov rdi, 0
    syscall

.usage:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel usage]
    mov rdx, usage_len
    syscall
    jmp .exit

; rdi = string hex (ate 16 digitos, prefixo 0x opcional) -> rax
parse_hex:
    xor eax, eax
    cmp byte [rdi], '0'
    jne .loop
    cmp byte [rdi + 1], 'x'
    je .skip_prefix
    cmp byte [rdi + 1], 'X'
    jne .loop
.skip_prefix:
    add rdi, 2
.loop:
    movzx ecx, byte [rdi]
    test cl, cl
    jz .done
    sub cl, '0'
    cmp cl, 9
    jbe .digit
    movzx ecx, byte [rdi]
    sub cl, 'a'
    add cl, 10
    cmp cl, 15
    jbe .digit
    movzx ecx, byte [rdi]
    sub cl, 'A'
    add cl, 10
    cmp cl, 15
    ja .done
.digit:
    shl rax, 4
    or rax, rcx
    inc rdi
    jmp .loop
.done:
    ret
