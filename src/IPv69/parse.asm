; parse.asm - parser IPv69
; parse_ipv69_frame(rdi = ptr frame, rsi = len) -> rax: 0 ok, 1 curto,
;   2 ethertype, 4 versao, 5 payload_len, 6 next_header
; print_ipv69_fields(rdi = ptr header) - imprime campos em hex, um por linha

%ifndef SYS_WRITE
%define SYS_WRITE 1
%endif
%ifndef STDOUT
%define STDOUT 1
%endif

%include "header.asm"

IPV69_ERR_SHORT     equ 1
IPV69_ERR_ETHERTYPE equ 2
IPV69_ERR_VERSION   equ 4
IPV69_ERR_LEN       equ 5
IPV69_ERR_NEXTHDR   equ 6

section .data
    sep_str   db " = "
    hex_chars db "0123456789abcdef"

    lbl_ver   db "ver_traffic"
    lbl_ver_len  equ $ - lbl_ver
    lbl_dscp  db "dscp_ecn"
    lbl_dscp_len equ $ - lbl_dscp
    lbl_plen  db "payload_len"
    lbl_plen_len equ $ - lbl_plen
    lbl_flow  db "flow_id"
    lbl_flow_len equ $ - lbl_flow
    lbl_next  db "next_header"
    lbl_next_len equ $ - lbl_next
    lbl_hop   db "hop_limit"
    lbl_hop_len  equ $ - lbl_hop
    lbl_flags db "flags"
    lbl_flags_len equ $ - lbl_flags
    lbl_seq   db "sequence"
    lbl_seq_len  equ $ - lbl_seq
    lbl_src   db "source"
    lbl_src_len  equ $ - lbl_src
    lbl_dst   db "dest"
    lbl_dst_len  equ $ - lbl_dst
    lbl_src_port db "src_port"
    lbl_src_port_len equ $ - lbl_src_port
    lbl_dst_port db "dst_port"
    lbl_dst_port_len equ $ - lbl_dst_port
    lbl_payload db "payload = "
    lbl_payload_len equ $ - lbl_payload

    ; [ptr label, len, offset no header, nbytes, pad]
    field_table:
        dq lbl_ver
        dd lbl_ver_len,  IPv69_Header.ver_traffic, 1, 0
        dq lbl_dscp
        dd lbl_dscp_len, IPv69_Header.dscp_ecn,    1, 0
        dq lbl_plen
        dd lbl_plen_len, IPv69_Header.payload_len, 2, 0
        dq lbl_flow
        dd lbl_flow_len, IPv69_Header.flow_id,     2, 0
        dq lbl_next
        dd lbl_next_len, IPv69_Header.next_header, 1, 0
        dq lbl_hop
        dd lbl_hop_len,  IPv69_Header.hop_limit,   1, 0
        dq lbl_flags
        dd lbl_flags_len,IPv69_Header.flags,       1, 0
        dq lbl_seq
        dd lbl_seq_len,  IPv69_Header.sequence,    4, 0
        dq lbl_src
        dd lbl_src_len,  IPv69_Header.source,      8, 0
        dq lbl_dst
        dd lbl_dst_len,  IPv69_Header.dest,        8, 0
        dq 0

section .text

parse_ipv69_frame:
    ; < 46 bytes (eth 14 + hdr 32)
    cmp rsi, Ethernet_Header_size + IPV69_HEADER_LEN
    jb .err_short

    movzx eax, word [rdi + Ethernet_Header.ethertype]
    cmp ax, ETHERTYPE_IPV69
    jne .err_ethertype

    ; versao = nibble alto do byte 0
    movzx eax, byte [rdi + Ethernet_Header_size + IPv69_Header.ver_traffic]
    shr al, 4
    cmp al, IPV69_VERSION
    jne .err_version

    ; payload_len <= frame - 46 (padding de ethernet permitido)
    movzx eax, word [rdi + Ethernet_Header_size + IPv69_Header.payload_len]
    bswap eax
    shr eax, 16
    sub rsi, Ethernet_Header_size + IPV69_HEADER_LEN
    cmp rax, rsi
    ja .err_len

    movzx eax, byte [rdi + Ethernet_Header_size + IPv69_Header.next_header]
    cmp al, 0
    je .ok
    cmp al, IPV69_NEXT_DGRAM
    je .ok
    cmp al, IPV69_NEXT_STREAM
    je .ok
    jmp .err_nexthdr

.ok:
    xor eax, eax
    ret

.err_short:
    mov eax, IPV69_ERR_SHORT
    ret
.err_ethertype:
    mov eax, IPV69_ERR_ETHERTYPE
    ret
.err_version:
    mov eax, IPV69_ERR_VERSION
    ret
.err_len:
    mov eax, IPV69_ERR_LEN
    ret
.err_nexthdr:
    mov eax, IPV69_ERR_NEXTHDR
    ret

; rdi = label, rsi = len, rdx = valor, ecx = nbytes (1/2/4/8)
print_hex_field:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15d, ecx

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rsi, r12
    mov rdx, r13
    syscall

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel sep_str]
    mov rdx, 3
    syscall

    ; buffer hex na stack: digitos + \n
    sub rsp, 32
    mov r9, rsp
    mov r8d, r15d
    shl r8d, 1
    lea r10, [r9 + r8]
    mov r11, r14
    mov ecx, r8d
.hloop:
    dec r10
    mov al, r11b
    and al, 0xF
    movzx eax, al
    mov al, [hex_chars + rax]
    mov [r10], al
    shr r11, 4
    dec ecx
    jnz .hloop
    mov byte [r9 + r8], 0xA

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rsi, r9
    lea rdx, [r8 + 1]
    syscall

    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rdi = ptr header ipv69 (offset 14 do frame)
print_ipv69_fields:
    push rbx
    push r12
    mov rbx, rdi
    lea r12, [rel field_table]
.ploop:
    mov rax, [r12]
    test rax, rax
    jz .pdone
    mov rdi, rax
    mov esi, [r12 + 8]
    mov eax, [r12 + 12]
    mov ecx, [r12 + 16]
    cmp ecx, 8
    je .ld64
    cmp ecx, 4
    je .ld32
    cmp ecx, 2
    je .ld16
    movzx edx, byte [rbx + rax]
    jmp .have
.ld64:
    mov rdx, [rbx + rax]
    bswap rdx
    jmp .have
.ld32:
    mov edx, [rbx + rax]
    bswap edx
    jmp .have
.ld16:
    movzx edx, word [rbx + rax]
    bswap edx
    shr edx, 16
.have:
    call print_hex_field
    add r12, 24
    jmp .ploop
.pdone:
    pop r12
    pop rbx
    ret

; rdi = ptr payload (apos o header), rsi = payload_len
; imprime src_port, dst_port e o payload como texto (nao imprimivel -> '.')
print_dgram253:
    cmp rsi, 4
    jb .done
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi

    movzx edx, word [r12]
    bswap edx
    shr edx, 16
    mov ecx, 2
    lea rdi, [rel lbl_src_port]
    mov esi, lbl_src_port_len
    call print_hex_field

    movzx edx, word [r12 + 2]
    bswap edx
    shr edx, 16
    mov ecx, 2
    lea rdi, [rel lbl_dst_port]
    mov esi, lbl_dst_port_len
    call print_hex_field

    ; payload formatado na stack: imprimivel vira char, resto '.'
    mov rbx, r13
    add rbx, 15
    and rbx, -16
    sub rsp, rbx
    mov r14, rsp
    xor ecx, ecx
.ploop:
    cmp ecx, r13d
    jae .pdone
    movzx eax, byte [r12 + rcx]
    cmp al, 0x20
    jb .dot
    cmp al, 0x7E
    ja .dot
    jmp .have
.dot:
    mov al, '.'
.have:
    mov [r14 + rcx], al
    inc ecx
    jmp .ploop
.pdone:
    mov byte [r14 + r13], 0xA

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [rel lbl_payload]
    mov rdx, lbl_payload_len
    syscall

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rsi, r14
    lea rdx, [r13 + 1]
    syscall

    add rsp, rbx
    pop r14
    pop r13
    pop r12
    pop rbx
.done:
    ret
