# ICSP — Improved Connection and Streaming Protocol

Transporte stream do IPv69 (next_header 2, reservado desde a v0.4).
SCTP melhorado: rouba o que o SCTP tem de bom e corrige as lacunas que
o impediram de virar padrão. Roda sobre o L2 do IPv69 (endereços 40-bit,
binding addr↔MAC no kernel, cripto Ed25519 já existente).

O objetivo é ser o "HTTPS próprio": um transporte confiável, ordenado,
multi-stream e **criptografado por padrão**, pronto para serviços
construídos sobre o IPv69.

---

## 1. O que roubar do SCTP (o bom)

| Feature | Por que manter |
|---|---|
| **Multi-streaming** | Uma associação com N streams independentes; evita head-of-line blocking do TCP (um dado lento não segura os outros) |
| **Message-oriented** | Preserva fronteiras de mensagem — não é byte-stream como TCP |
| **Handshake 4-way com cookie** | INIT → INIT-ACK(cookie) → COOKIE-ECHO → COOKIE-ACK; o servidor fica stateless até o cookie voltar (anti-flood de conexão) |
| **SACK seletivo + retransmissão** | Reenvia só o que faltou, não a janela inteira |
| **Heartbeat** | Detecta caminho morto e faz failover |
| **CRC32c** | Checksum forte por pacote |
| **Multi-homing** | Um endpoint com vários endereços (failover transparente) |

## 2. As lacunas do SCTP e como o ICSP resolve

| Problema do SCTP | Solução ICSP |
|---|---|
| **Sem criptografia nativa** — DTLS-over-SCTP é um patch posterior | Handshake autenticado + fluxo criptografado embutido: identidade Ed25519 (auto-key `~/.ipv69/key`) + X25519 efêmera (ECDH) + XSalsa20-Poly1305 (secretbox). Estilo mini-Noise: assina 1x, deriva chave simétrica de sessão |
| **Complexidade absurda** — RFC 4960 ≈ 150 páginas + dezenas de extensões | Subset essencial: ~10 tipos de chunk, sem extensões opcionais. Estados: CLOSED → COOKIE_WAIT → ESTABLISHED → SHUTDOWN. Só |
| **NAT/middlebox quebra tudo** | Não existe no IPv69: L2 puro, endereço 40-bit global na rede. Lacuna eliminada por design |
| **Cookie fraco / sem segredo** | Cookie = chave secreta efêmera do servidor (rotacionada) + hash dos parâmetros; cliente não consegue forjar |
| **Streams fixos na associação** | STREAM-RESET nativo (renegociação dinâmica, como RFC 6525) |
| **Sem sessão reutilizável** | 0-RTT opcional: COOKIE-ECHO pode carregar dados já criptografados quando há sessão reutilizável |

## 3. Arquitetura

```
┌──────────────────────────────────────────────┐
│  Serviço / app (mensagens por stream)         │
├──────────────────────────────────────────────┤
│  ICSP (next_header 2)                        │
│  associação, streams, TSN/SACK, cripto AEAD  │
├──────────────────────────────────────────────┤
│  IPv69 L2 (next_header 0/1/2, 40-bit,        │
│  binding addr↔MAC, Ed25519 p/ bootstrap)     │
└──────────────────────────────────────────────┘
```

O IPv69 entrega **datagramas** (nh=1) e **controle** (nh=0). O ICSP
consome o mesmo L2 mas com semântica de **fluxo confiável**: o que o
dgram não garante (ordem, entrega, conexão) é responsabilidade do ICSP.

## 4. Wire format (rascunho)

```
Frame IPv69 (nh=2): [header 38B] + payload ICSP

Header ICSP (12B):
  src_port  (2)  dst_port (2)
  ver       (1)  flags    (1)
  assoc_id  (4)
  crc32c    (2)   ← checksum da associação (forte, como SCTP)

Chunks (todos): [type 1][flags 1][len 2][dados...]
```

Tipos de chunk (numeração limpa 0–9):

```
0  DATA          [tsn 4][stream_id 2][stream_seq 2][payload]
1  INIT          [ver][streams_in 2][streams_out 2][eph_pub 32][id_pub 32][sig 64]
2  INIT-ACK      [ver][streams][eph_pub 32][id_pub 32][sig 64][cookie]
3  COOKIE-ECHO   [cookie][dados 0-RTT opcionais]
4  COOKIE-ACK
5  SACK          [tsn_cumulativo 4][gaps...]
6  HEARTBEAT
7  HEARTBEAT-ACK
8  SHUTDOWN
9  STREAM-RESET  [stream_id 2][modo 1]
```

Cripto por chunk DATA: `secretbox(tsn|stream|seq|payload)` com nonce
derivado de (assoc_id, tsn) — autenticado por pacote, replay protegido
por janela deslizante.

## 5. Handshake (Fase 1)

1. **Cliente → INIT**: pub identidade (Ed25519, do auto-key) + pub efêmera X25519 + streams desejados, assinado.
2. **Servidor → INIT-ACK**: pub do servidor + pub efêmera + cookie (chave secreta + hash) + streams aceitos, assinado.
3. **Cliente → COOKIE-ECHO**: devolve o cookie (prova que o INIT-ACK veio do servidor legítimo) + assinatura.
4. **Servidor → COOKIE-ACK**: valida o cookie, associação ESTABLISHED.

Derivação de chave: `shared = X25519(eph_priv, peer_eph_pub)` →
`session_key = SHA-512(shared || assoc_id || nonces)` → secretbox com
`key[0..31]` e nonces derivados por pacote. As identidades Ed25519
autenticam quem está do outro lado (mesma allowlist de pubkeys do DHCP).

## 6. Estrutura de pastas

```
include/ICSP/icsp.h          — API pública + constantes de wire
include/ICSP/icsp_internal.h — estruturas internas (associação, streams)
src/ICSP/icsp.c              — núcleo: associação, estados, chunk RX/TX
src/ICSP/icsp_handshake.c    — INIT/cookie/derivação de chave
src/ICSP/icsp_data.c         — streams, TSN, SACK, retransmissão
src/ICSP/icsp_heartbeat.c    — heartbeat + failover
tests/icsp_test.c            — par servidor/cliente de teste
docs/icsp-spec.md            — este documento
```

A lib `lib/ed25519` ganha wrappers expostos: `nacl_scalarmult` (X25519)
e `nacl_secretbox_*` (AEAD) — já existem no tweetnacl.c, só expor com
API limpa.

## 7. Fases (cada uma testável)

| Fase | Escopo | Critério de aceite |
|---|---|---|
| **1 — Infra + handshake** | pastas, Makefile, header/chunks, INIT→COOKIE-ACK autenticado (Ed25519 + X25519 → chave de sessão) | `icsp_test client/server` no veth completa o handshake; chave derivada igual nos dois lados; assinatura inválida = recusa |
| **2 — Dados** | DATA criptografado, TSN/SACK, retransmissão, streams múltiplos | entrega ordenada; perda sintética é recuperada; stream A não segura stream B |
| **3 — Vida** | heartbeat, shutdown gracioso, STREAM-RESET | caminho cai → failover; shutdown limpa associação; streams renegociados em runtime |
| **4 — Host→host** | celular ↔ VM, auto-key, binding | mesma experiência do veth, mas pela rede real (Wi-Fi ↔ bridge) |

## 8. Fora de escopo (de propósito)

- Controle de congestionamento complexo (CUBIC etc.) — rede L2 privada,
  janela simples; evolui depois se necessário.
- MTU discovery / fragmentação de associação — IPv69 tem flag NOFRAG;
  payload ≤ 1400.
- Extensões exóticas do SCTP (ADDIP, PR-SCTP, ASCONF) — só STREAM-RESET.

## 9. Dependências

Nenhuma nova. Tudo o que o ICSP precisa já existe no repo:

- `lib/ed25519` (TweetNaCl + wrapper): sign/verify p/ handshake,
  scalarmult p/ ECDH, secretbox p/ AEAD (a expor).
- IPv69 L2: entrega de frames com endereçamento 40-bit e binding.
- auto-key `~/.ipv69/key`: identidade do device, mesma do DHCP.
