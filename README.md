# IPv69 — Protocolo de Rede Experimental

## Visão geral

O IPv69 é um protocolo meme que realmente vai ser usado pra altas paradas, ferramentas que exclusivamente vão funcionar em IPv69 e todos os seus protocolos dependentes.

A ideia do projeto não é apenas criar um novo formato de pacote, mas eventualmente construir uma stack de rede completa baseada no IPv69, capaz de ser implementada em software, sistemas embarcados e, futuramente, até em hardware dedicado.

O projeto está sendo desenvolvido inicialmente em Assembly x86-64, permitindo trabalhar diretamente com memória, bytes, sockets e interfaces de rede sem depender de abstrações de alto nível.

## Objetivos

A ideia final é que um sistema possa funcionar essencialmente assim:

```text
Aplicação
    ↓
Socket IPv69
    ↓
Stack IPv69
    ↓
Ethernet / Wi-Fi
    ↓
Driver
    ↓
Hardware
```

## Estado atual do projeto
Estado atual do projeto
### 1. Header IPv69

Já foi definida uma primeira estrutura para o header IPv69.

A proposta atual utiliza um header fixo de 32 bytes, evitando a necessidade de um campo equivalente ao IHL do IPv4.

Características definidas até agora:

- header fixo de 32 bytes;
- sem campo IHL;
- sem campo de opções dentro do header principal;
- possibilidade de utilizar extension headers, seguindo uma ideia semelhante à arquitetura do IPv6;
- endereços de 64 bits;
- campos transmitidos em big-endian / network byte order;
- sem checksum no header;
- sem fragmentação;
- EtherType experimental: `0x6969`.

A estrutura ainda é experimental e pode mudar conforme a implementação evoluir.

### 2. Macros Assembly para Big-Endian

Foram criadas macros em NASM para facilitar a construção dos campos do protocolo em big-endian:

- `BE16`
- `BE32`
- `BE64`

Isso permite construir o pacote corretamente mesmo estando em uma arquitetura x86-64, que utiliza little-endian.

Exemplo conceitual:

```text
CPU x86-64
    ↓
little-endian

IPv69 na rede
    ↓
big-endian
```

Portanto, a implementação precisa realizar explicitamente a conversão entre a representação nativa da CPU e a representação utilizada pelo protocolo.

### 3. Detector / Receiver IPv69

O primeiro componente funcional do projeto é um detector de pacotes IPv69 desenvolvido em Assembly x86-64.

Ele utiliza:

- `AF_PACKET`
- `SOCK_RAW`
- `ETH_P_ALL`

para receber diretamente os frames Ethernet através do kernel Linux.

A estrutura atual é aproximadamente:

      ```text
        Ethernet Frame
              │
              ▼
       AF_PACKET socket
              │
              ▼
       Assembly receiver
              │
              ▼
        Ethernet header
              │
              ▼
         EtherType
              │
         0x6969 ?
          /     \
        não      sim
        │         │
      ignora    IPv69
                  │
                  ▼
             parse header
```

O objetivo dessa etapa é conseguir identificar e posteriormente interpretar pacotes IPv69 diretamente na interface de rede.

### 4. Testes com Python

Para não precisar desenvolver transmissor e receptor simultaneamente em Assembly, foi utilizado um programa em Python como ferramenta de teste.

A ideia é:

```text
Python
  │
  │ gera pacote IPv69
  ▼
Rede / interface
  │
  ▼
Receiver Assembly
```

Isso permite validar o parser e o formato do pacote antes de implementar todos os componentes em Assembly.

### 5. Parser IPv69 (Assembly)

O detector evoluiu para um parser com validação (`src/parse.asm`), usado pelo receiver:

- `parse_ipv69_frame(rdi = ptr frame, rsi = len)` → `rax = 0` se válido, ou código de erro;
- `print_ipv69_fields(rdi = ptr header)` → imprime todos os campos em hex;
- leitura de campos multi-byte com `bswap` (rede big-endian → nativo little-endian).

Regras de validação atuais:

1. frame ≥ 46 bytes (Ethernet 14 + header 32);
2. EtherType == `0x6969`;
3. versão (nibble alto do byte 0) == 6;
4. `payload_len` ≤ frame_len − 46 (padding de Ethernet permitido);
5. `next_header` ∈ {0, 253, 254}.

Códigos de erro: `1` frame curto, `2` EtherType errado, `4` versão errada, `5` payload_len inconsistente, `6` next_header desconhecido.

### 6. Transmissor IPv69 (Assembly)

`src/send.asm` monta um frame Ethernet II completo e transmite via `AF_PACKET`/`SOCK_RAW`:

- MAC de origem lida da interface via `SIOCGIFHWADDR`, destino broadcast;
- header montado a partir de um template (macros `BE16`/`BE32`/`BE64`);
- `payload_len` e endereço destino preenchidos em runtime;
- padding até o mínimo de 60 bytes do frame Ethernet.

### 7. Build e uso

```text
make                     # compila ipv69, ipv69_send

sudo ./ipv69 eth0        # receiver (root: raw socket)
sudo ./ipv69_send eth0   # sender (root: raw socket)
```

O transmissor aceita argumentos opcionais:

```text
sudo ./ipv69_send <interface> [dest_hex] [payload]
sudo ./ipv69_send eth0 2 "oi"        # dest = 0x2, payload "oi"
sudo ./ipv69_send eth0 0xdeadbeef    # dest = 0xdeadbeef
```

### 8. Comunicação host → host (validada)

Primeira comunicação IPv69 real entre duas máquinas na mesma rede:

- host A: Moto G22 (root) com chroot Kali arm64 rodando o binário x86_64 via QEMU user-mode, interface `wlan0` (Wi-Fi);
- host B: VM Kali no VirtualBox com adaptador bridged na Ethernet, interface `eth0` (cabo);
- roteador doméstico fazendo bridge L2 entre Wi-Fi e porta LAN.

O frame enviado pelo `ipv69_send` no celular foi recebido, validado e impresso pelo `ipv69` na VM — atravessando Wi-Fi, roteador e cabo. Detalhe: o WSL2 não participa (NAT não encaminha frames raw); o lado PC precisa de um Linux com acesso L2 à interface física.

## Especificação do header IPv69 (v0.1)

Header fixo de 32 bytes, big-endian na rede, sem checksum, sem fragmentação.

| off | tam | campo       | descrição                                                        |
|-----|-----|-------------|------------------------------------------------------------------|
| 0   | 1   | ver_traffic | versão (4 bits, = 6) + traffic class (4 bits, = 9) → byte `0x69` |
| 1   | 1   | dscp_ecn    | DSCP (6 bits) + ECN (2 bits)                                     |
| 2   | 2   | payload_len | tamanho do payload (o header é sempre 32 bytes)                  |
| 4   | 2   | flow_id     | hash para ECMP/balanceamento, QoS por fluxo, demux               |
| 6   | 1   | next_header | protocolo ou primeiro extension header (0 = sem payload)         |
| 7   | 1   | hop_limit   | decrementado por hop; descarta em 0                              |
| 8   | 1   | flags       | bit0 NOFRAG, bit1 JUMBO, bits 2–7 experimentais                  |
| 9   | 1   | reserved    | zero                                                             |
| 10  | 2   | reserved2   | uso futuro (mantém `sequence` alinhado em 4)                     |
| 12  | 4   | sequence    | anti-replay / reordenação / estado de conexão                    |
| 16  | 8   | source      | endereço 64-bit                                                  |
| 24  | 8   | dest        | endereço 64-bit                                                  |
| 32  | —   | total       | = 4 qwords → cópia do header inteiro = 4 `mov r64`               |

### next_header

| valor | significado                                      |
|-------|--------------------------------------------------|
| 0     | sem payload                                      |
| 253   | datagrama simples: `src_port`(2) + `dst_port`(2) + dados |
| 254   | stream (futuro, SCTP-like)                       |

Alinhado com IANA onde possível: 1 ICMP, 2 IGMP, 6 TCP, 17 UDP, 41 ENCAP, 89 OSPF, 132 SCTP. (253/254 são os números IANA de experimentação.)

### flags

| bit | nome    | significado                              |
|-----|---------|------------------------------------------|
| 0   | NOFRAG  | não fragmentar (endpoints fazem PMTUD)   |
| 1   | JUMBO   | payload > 65535 (via extension header)   |

### Decisões de design

- Sem IHL e sem campo de opções: header imutável de 32 bytes; opções viram cadeia de extension headers (estilo IPv6).
- Sem checksum no header: CRC da Ethernet (camada 2) + checksum da camada 4 cobrem a integridade.
- Sem fragmentação: endpoints fazem PMTUD; existe apenas a flag NOFRAG.
- Endereços de 64 bits: meio-termo entre IPv4 (32) e IPv6 (128).
- EtherType experimental `0x6969` (≥ 0x0600 → válido, uso experimental/local).

## O que ainda falta

O detector atual é apenas o começo. Para transformar o IPv69 em uma stack de rede utilizável, ainda existem várias etapas.

### 1. Evoluir a especificação do header

A v0.1 está fechada (tabela acima), mas ainda falta definir:

- extension headers (formato, encadeamento, JUMBO);
- regras de parsing para pacotes com extension headers;
- tratamento de pacotes inválidos (política de descarte/log);
- valores reservados;
- MTU padrão.

### 2. Evoluir o parser

O parser básico já valida tamanho, versão, payload_len e next_header. Falta:

- parsing de cadeia de extension headers;
- validação do datagrama 253 (src_port/dst_port/dados);
- limites de buffer e contadores mais estritos (debug de malformados);
- desempacotamento do payload (camada 4).

### 3. Gerador de pacotes

O gerador básico existe (`ipv69_send`). Falta:

- opções de linha de comando (source, flow_id, sequence, hop_limit, flags);
- montagem de datagrama 253 com portas;
- geração de extension headers;
- geração programática a partir de uma API (não só CLI).

### 4. Transmissão e recepção reais

O caminho básico funciona via raw socket, mas ainda falta:

- teste de comunicação host → host (dois WSL/dois hosts na mesma rede);
- recepção com entrega de payload (hoje o receiver só imprime o header);
- integração futura com a infraestrutura de rede do sistema operacional.

### 5. Endereçamento

Será necessário definir completamente como os endereços IPv69 funcionam.

A proposta atual utiliza endereços de 64 bits.

Ainda precisam ser definidas questões como:

- endereço de rede;
- prefixos;
- endereço local;
- broadcast/multicast, caso existam;
- loopback;
- autoconfiguração;
- resolução de endereços;
- representação textual;
- subnetting.
### 6. Routing

Depois que dois dispositivos conseguirem conversar diretamente, será necessário implementar roteamento:

```text
Host A
  │
  ▼
Router IPv69
  │
  ▼
Router IPv69
  │
  ▼
Host B
```

Isso envolve:

- tabela de rotas;
- next-hop;
- forwarding;
- decremento do Hop Limit;
- mensagens de erro;
- descoberta de rotas;
- eventualmente um protocolo de roteamento próprio.
### 7. Transporte

O IPv69 é uma camada de rede.

Para aplicações reais, será necessário definir o que vem acima dele.

Possibilidades:

```text
IPv69
 ├── UDP-like
 ├── TCP-like
 └── protocolo de transporte próprio
```

Ou eventualmente implementar versões adaptadas de protocolos existentes.

### 8. Integração com o sistema operacional

Em algum momento será necessário deixar de depender exclusivamente de raw sockets.

A arquitetura desejada seria algo semelhante a:

```text
Aplicação
    ↓
socket(AF_69, ...)
    ↓
IPv69
    ↓
Ethernet
    ↓
driver da NIC
    ↓
hardware
```

Isso provavelmente exigirá uma implementação da camada IPv69 dentro do sistema operacional ou um módulo específico.

Importante: criar o IPv69 não significa necessariamente criar um novo driver para cada placa de rede.

O driver existente continua responsável por controlar a NIC, enquanto a implementação do IPv69 fica acima dele.

## Implementação em hardware

Uma etapa futura do projeto é investigar a implementação do IPv69 diretamente em dispositivos embarcados ou hardware dedicado.

Possíveis plataformas:

```text
Microcontrolador
      ↓
Firmware IPv69
```

ou:

```text
FPGA
 ↓
Ethernet MAC
 ↓
IPv69 hardware parser
 ↓
CPU / lógica
```

e, em uma etapa muito mais avançada:

```text
ASIC / NIC dedicada
        ↓
    IPv69
  ```

Nesse cenário, partes do processamento do protocolo poderiam ser realizadas diretamente em hardware.

## Arquitetura pretendida

A visão de longo prazo do projeto é chegar a uma arquitetura semelhante a:

```text
┌──────────────────────────────┐
│          Aplicações          │
├──────────────────────────────┤
│        Socket / API          │
├──────────────────────────────┤
│         Transporte           │
├──────────────────────────────┤
│            IPv69             │
│                              │
│  Addressing                  │
│  Routing                     │
│  Forwarding                  │
│  Extension Headers           │
├──────────────────────────────┤
│       Ethernet / Wi-Fi       │
├──────────────────────────────┤
│           Driver             │
├──────────────────────────────┤
│           Hardware           │
└──────────────────────────────┘
```

## Roadmap

### Fase 1 — Protocolo
- [x] Definir conceito do IPv69
- [x] Definir header inicial
- [x] Definir endereços de 64 bits
- [x] Definir EtherType experimental `0x6969`
- [x] Definir utilização de big-endian
- [x] Criar macros `BE16`, `BE32` e `BE64`
- [x] Finalizar especificação do header (v0.1)
- [ ] Definir extension headers
- [x] Definir regras de parsing (validação básica em `parse.asm`)

### Fase 2 — Packet I/O
- [x] Criar detector em Assembly
- [x] Capturar frames via `AF_PACKET`
- [x] Identificar EtherType `0x6969`
- [x] Fazer parsing completo do header
- [x] Validar pacotes (básico)
- [x] Criar gerador de pacotes
- [x] Transmitir pacotes (raw socket)
- [x] Comunicação IPv69 host → host (Kali/QEMU no celular ↔ VM VirtualBox bridged)

### Fase 3 — Stack
- Addressing
- Routing
- Forwarding
- Hop Limit
- ICMP-like / mensagens de controle
- Protocolo de transporte
- API/socket

### Fase 4 — Sistema operacional
- Definir API de integração
- Implementar suporte IPv69 no Linux
- Criar interface de rede IPv69
- Integrar com drivers existentes
- Testar aplicações reais sobre IPv69

### Fase 5 — Embedded
- Implementação em microcontrolador
- Implementação em ESP32
- Implementação Ethernet
- Implementação Wi-Fi
- Testes entre PC e dispositivo embarcado

### Fase 6 — Hardware
- Parser IPv69 em FPGA
- Processamento de headers em hardware
- Investigação de NIC IPv69
- Possível implementação ASIC

## Estado atual

IPv69 está atualmente na fase de experimentação do protocolo e implementação do packet detector.

O objetivo imediato não é substituir a Internet existente, mas construir uma stack de rede experimental do zero, começando pelo nível mais baixo possível:

```text
bytes
  ↓
Ethernet
  ↓
IPv69
  ↓
transporte
  ↓
aplicação
```

A implementação inicial em Assembly serve para tornar explícito todo o processo de construção, transmissão, recepção e interpretação dos pacotes, antes de adicionar abstrações de mais alto nível.