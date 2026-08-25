; ipv69 - receiver: AF_PACKET/SOCK_RAW, filtra EtherType 0x6969,
; valida o header IPv69 (parse.asm) e imprime os campos
; Uso: sudo ./ipv69 <interface>

SYS_SOCKET   equ 41
SYS_BIND     equ 49
SYS_RECVFROM equ 45
SYS_WRITE    equ 1
SYS_EXIT     equ 60
SYS_IOCTL    equ 16

AF_PACKET    equ 17
SOCK_RAW     equ 3

ETH_P_ALL    equ 0x0003

SIOCGIFINDEX equ 0x8933
IFNAMSIZ     equ 16

STDOUT       equ 1

%include "header.asm"
%include "bigendian.asm"
%include "parse.asm"

section .bss
    buffer resb 65536
    ifreq  resb 40

section .data
    sockaddr_ll:
        dw AF_PACKET
        dw 0x0300           ; htons(ETH_P_ALL)
        dd 0                ; ifindex (runtime)
        dw 0
        db 0
        db 0
        times 8 db 0

    msg_ipv69 db "IPv69 frame received!", 0xA
    msg_ipv69_len equ $ - msg_ipv69

    newl db 0xA

    msg_bad db "invalid IPv69 frame (code="
    msg_bad_len equ $ - msg_bad
    msg_bad_end db ")", 0xA
    msg_bad_end_len equ $ - msg_bad_end

    usage db "Usage: sudo ./ipv69 <interface>", 0xA
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
    mov rdx, 0x0300
    syscall
    test rax, rax
    js .exit
    mov r12, rax

    mov rdi, [rsp + 16]
    lea rsi, [rel ifreq]
.copy_interface:
    mov al, [rdi]
    mov [rsi], al
    inc rdi
    inc rsi
    test al, al
    jnz .copy_interface

    mov rax, SYS_IOCTL
    mov rdi, r12
    mov rsi, SIOCGIFINDEX
    lea rdx, [rel ifreq]
    syscall
    test rax, rax
    js .exit

    mov eax, [ifreq + 16]
    mov [sockaddr_ll + 4], eax

    mov rax, SYS_BIND
    mov rdi, r12
    lea rsi, [rel sockaddr_ll]
    mov rdx, 20
    syscall
    test rax, rax
    js .exit

.receive:
    mov rax, SYS_RECVFROM
    mov rdi, r12
    lea rsi, [rel buffer]
    mov rdx, 65536
    xor r8, r8
    xor r9, r9
    xor r10, r10
    syscall
    test rax, rax
    js .exit

    ; frame = [dst 6 | src 6 | ethertype 2 | header ipv69 | payload]
    ; ETH_P_ALL pega tudo: descarta nao-IPv69 em silencio
    movzx eax, word [rel buffer + Ethernet_Header.ethertype]
    cmp ax, ETHERTYPE_IPV69
    jne .receive

    lea rdi, [rel buffer]
    mov rsi, rax
    call parse_ipv69_frame
    test rax, rax
    jnz .bad

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel msg_ipv69]
    mov rdx, msg_ipv69_len
    syscall

    lea rdi, [rel buffer + Ethernet_Header_size]
    call print_ipv69_fields

    ; datagrama 253: portas + dados
    movzx eax, byte [rel buffer + Ethernet_Header_size + IPv69_Header.next_header]
    cmp al, IPV69_NEXT_DGRAM
    jne .no_dgram
    movzx eax, word [rel buffer + Ethernet_Header_size + IPv69_Header.payload_len]
    bswap eax
    shr eax, 16
    test eax, eax
    jz .no_dgram
    lea rdi, [rel buffer + Ethernet_Header_size + IPV69_HEADER_LEN]
    mov esi, eax
    call print_dgram253
.no_dgram:

    ; linha em branco separando os frames
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel newl]
    mov rdx, 1
    syscall

    jmp .receive

.bad:
    mov rbx, rax
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel msg_bad]
    mov rdx, msg_bad_len
    syscall

    sub rsp, 16
    mov al, bl
    add al, '0'             ; codigo 1-6 -> char
    mov [rsp], al
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rsi, rsp
    mov rdx, 1
    syscall
    add rsp, 16

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel msg_bad_end]
    mov rdx, msg_bad_end_len
    syscall
    jmp .receive

.usage:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel usage]
    mov rdx, usage_len
    syscall

.exit:
    mov rax, SYS_EXIT
    mov rdi, 0
    syscall
