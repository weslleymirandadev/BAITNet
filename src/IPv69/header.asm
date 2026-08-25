; ============================================================================
; IPv69 - header layout (draft)
;
%ifndef IPV69_HEADER_ASM
%define IPV69_HEADER_ASM
;
; Design decisions (vs IPv4):
;   - Fixed 32-byte header: no IHL, no options field. Options become a
;     chain of extension headers (IPv6-style), pointed by .next_header.
;   - No header checksum: Ethernet CRC (layer 2) + layer 4 cover integrity.
;   - No fragmentation: endpoints do PMTUD; only a no-fragment flag exists.
;   - 64-bit addresses (IPv4=32, IPv6=128, this is the fun middle ground).
;   - Big-endian on the wire (network byte order), like IPv4/IPv6.
;   - Runs directly on Ethernet II:
;       [ dst MAC 6 | src MAC 6 | EtherType 2 | IPv69 hdr | payload | CRC 4 ]
;     EtherType 0x6969 (>= 0x0600 -> valid, experimental/local use).
;     Note: Ethernet minimum frame is 64 bytes -> if hdr+payload < 46 bytes
;     the layer-2 driver must pad the payload.
;
; Alignment: every field sits at its natural alignment (word at even offset,
; dword at *4, qword at *8), so multi-byte fields are read straight from the
; wire buffer with plain movs - only the loaded value needs a bswap for
; byte order. The header is exactly 4 qwords, so a full copy = 4 mov r64.
; ============================================================================

ETHERTYPE_IPV69     equ 0x6969

IPV69_VERSION       equ 6          ; high nibble of byte 0
IPV69_TRAFFIC_CLASS equ 9          ; low nibble  -> byte 0 = 0x69 ;)
IPV69_HEADER_LEN    equ 32

; next_header values (local/experimental transport sketch)
; 253/254 are the IANA experimentation-and-testing numbers
IPV69_NEXT_DGRAM   equ 253   ; simple datagram: src_port(2) + dst_port(2) + data
IPV69_NEXT_STREAM  equ 254   ; future SCTP-like transport (streams + chunks)

; .flags bits
IPV69_FLAG_NOFRAG   equ 1 << 0     ; do not fragment
IPV69_FLAG_JUMBO    equ 1 << 1     ; payload > 65535 (via extension header)

; ============================================================================
; Field map (offsets fixed - header is immutable 32 bytes):
;
;   off  size  field         notes
;   ---  ----  ------------  ---------------------------------------------
;   0    1     ver_traffic   version(4) = 6 + traffic class(4) = 9 -> 0x69
;   1    1     dscp_ecn      DSCP(6) + ECN(2)
;   2    2     payload_len   payload only (header size is a constant)
;   4    2     flow_id       ECMP/load-balancing hash, per-flow QoS, demux
;   6    1     next_header   protocol or first ext-header (0 = no payload)
;   7    1     hop_limit     decremented per hop, drop at 0
;   8    1     flags         bit0 NOFRAG, bit1 JUMBO, bits2-7 experimental
;   9    1     reserved
;   10   2     reserved2     future use (keeps .sequence 4-aligned)
;   12   4     sequence      anti-replay / reorder detection / conn state
;   16   8     source        64-bit address
;   24   8     dest          64-bit address
;   ---  ----  ------------
;   32   total               = 4 qwords -> full header copy = 4 mov r64
;
; Protocol numbers (keep aligned with IANA where possible)
; Number | Protocol name                               | Abbreviation
;--------+---------------------------------------------+-------------
;      1 | Internet Control Message Protocol            | ICMP
;      2 | Internet Group Management Protocol           | IGMP
;      6 | Transmission Control Protocol                | TCP
;     17 | User Datagram Protocol                       | UDP
;     41 | IPv6 encapsulation                           | ENCAP
;     89 | Open Shortest Path First                     | OSPF
;    132 | Stream Control Transmission Protocol         | SCTP
; ============================================================================

struc Ethernet_Header
    .dst_mac    resb 6   ; offset 0
    .src_mac    resb 6   ; offset 6
    .ethertype  resw 1   ; offset 12  (0x6969 = IPv69)
endstruc
; Ethernet_Header_size = 14

struc IPv69_Header
    .ver_traffic resb 1  ; offset 0
    .dscp_ecn    resb 1  ; offset 1
    .payload_len resw 1  ; offset 2
    .flow_id     resw 1  ; offset 4
    .next_header resb 1  ; offset 6
    .hop_limit   resb 1  ; offset 7
    .flags       resb 1  ; offset 8
    .reserved    resb 1  ; offset 9
    .reserved2   resw 1  ; offset 10
    .sequence    resd 1  ; offset 12
    .source      resq 1  ; offset 16
    .dest        resq 1  ; offset 24
endstruc
; IPv69_Header_size = 32

%endif
