# IPv69 — Manual de uso

Protocolo experimental próprio (EtherType `0x6969`, endereços 40-bit,
família de socket `AF_69`) com DHCP69 (auto-configuração de endereço) e
autenticação Ed25519. Tudo roda em L2 — sem IP, sem roteador, sem
internet.

```
┌─────────────────┐   Wi-Fi / cabo (Ethernet)   ┌─────────────────┐
│  celular (raw)  │ ───────────────────────────▶ │  VM Kali (módulo│
│  sem AF_69      │ ◀─────────────────────────── │  af69.ko)       │
└─────────────────┘                              └─────────────────┘
```

## O que é o quê

| Binário | Papel | Onde roda |
|---|---|---|
| `af69d` | **Servidor DHCP69** (aloca endereços do pool, valida chaves, registra binding no kernel) | VM |
| `af69_raw` | Cliente genérico (recv/send/ping/dhcp) via AF_PACKET, **sem módulo** | celular (arm64) e VM |
| `af69_test` | Cliente genérico via socket `AF_69` (**requer módulo**) | VM |
| `ipv69-keygen` | Gera pares de chaves Ed25519 | qualquer host |
| `ip69d` | Daemon de interface: segura um endereço DHCP e cria a TAP `ip69-0` | celular/VM |
| `ip69` | Consulta o `ip69d` (como `ip addr` pro IPv69) | mesmo host do ip69d |

Além dos binários, o projeto tem a **lib de cripto separada**:

| Caminho | O que é |
|---|---|
| `lib/ed25519/include/ed25519.h` | API pública (keypair, sign, verify, keyfile) |
| `lib/ed25519/src/` | Implementação (`ed25519.c` + `tweetnacl.c` + `randombytes.c`) |

Ela não depende de nada do IPv69 — pode ser reutilizada em qualquer
projeto (o seu "HTTPS próprio" futuro, por exemplo). Detalhes na seção 8.

## Endereços e portas

- Endereços: 40-bit, formato `00.00.00.00.10` (5 octetos)
  - `00.00.00.00.01` = servidor DHCP (reservado)
  - `00.00.00.00.10`–`00.00.00.00.fe` = pool DHCP (padrão)
  - `ff.ff.ff.ff.ff` = broadcast
- Portas: **hexadecimal** na CLI (`10` = 16 decimal)
- `next_header`: `0` controle (DHCP/ND/echo), `1` dgram, `2` stream (reservado)

---

## 1. Chaves (quase automático)

Cada device tem a SUA chave. **A privada nunca sai do device**; o
servidor só conhece **públicas** (não são segredo).

### Auto-key (recomendado)

Todos os clientes (`af69_raw`, `af69_test`, `ip69d`) geram a chave
sozinhos na primeira execução e guardam o seed em `~/.ipv69/key`
(0600). Rode uma vez e copie a PUBKEY que ele imprime:

```bash
export HOME=/root          # importante no chroot do celular!
/root/bin/af69_raw dhcp wlan0    # 1a vez: gera a chave e imprime:
#   chave gerada em /root/.ipv69/key
#   registre esta PUBKEY no servidor:
#   616833cf40e2708d42db3626c1a8e7f7434dc5bfcd2f004c5b6d4ec541379822
```

Da segunda vez em diante ele carrega `~/.ipv69/key` e usa a mesma
identidade — semelhante ao modelo SSH (`~/.ssh/id_ed25519`).

### Manual (opcional)

```bash
./ipv69-keygen 2
<privkey_hex> <pubkey_hex>      # linha 1: device A (ex: celular)
<privkey_hex> <pubkey_hex>      # linha 2: device B (ex: servidor/VM)
```

Depois é só passar `--key <privkey_hex>` (e `--server-pub <pubkey_hex>`
nos clientes) — o auto-key é dispensado quando `--key` é dado.

---

## 2. Subir o servidor DHCP (VM)

### Auto-registro (`--learn`) — zero cadastro manual

```bash
# o servidor aceita qualquer pubkey com assinatura válida e registra
# sozinho (append no --peer-file, se dado):
sudo ./af69d eth0 --raw --peer-file /home/kali/peers.txt --learn \
     --key <privkey_do_servidor_hex>   # opcional: assina OFFER/ACK

# log:
#   af69d: aprendi pub 8566295b... do MAC 00:08:22:9c:03:fc -> registrada no peer-file
#   af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
#   af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

O celular roda `dhcp wlan0` e pronto — sem copiar hex nenhum. O
`--learn` sem `--allow` é **rede aberta** (qualquer um com chave entra);
com `--allow MAC...` ele restringe o aprendizado só aos MACs listados.

### Com arquivo de peers (fechado — reload automático)

```bash
# 1) crie o arquivo com as PUBKEYs permitidas (1 por linha):
echo '616833cf40e2708d42db3626c1a8e7f7434dc5bfcd2f004c5b6d4ec541379822' > /home/kali/peers.txt

# 2) suba o servidor apontando para ele:
sudo ./af69d eth0 --raw --peer-file /home/kali/peers.txt \
     --key <privkey_do_servidor_hex>
```

**Adicionar um device novo = editar o arquivo.** O servidor percebe a
mudança sozinho (checa o mtime do arquivo a cada ~1s) e passa a aceitar
a nova pubkey — sem reiniciar, sem sinal:

```bash
echo 'outra_pubkey_hex' >> /home/kali/peers.txt   # vale na hora
```

### Com chave única na linha de comando

```bash
sudo ./af69d eth0 --raw \
     --allow 00:08:22:9c:03:fc \        # (opcional) MACs permitidos
     --peer  <pubkey_do_celular_hex> \  # só quem tem essa pub entra
     --key   <privkey_do_servidor_hex>  # assina OFFER/ACK (anti rogue)
```

Log esperado:

```
af69d: raw AF_PACKET (ifindex 2), pool 0000000000000010-00000000000000fe lease 3600s
af69d: allow=1 mac(s), peers=1 pubkey(s), server-key=sim
af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

Rejeições aparecem assim:

```
af69d: pub f38f9008... nao esta na allowlist -> ignorado
af69d: 00:08:22:9c:03:fc assinatura/pubkey invalida -> ignorado
```

> `--raw` é obrigatório quando o AP/roteador filtra broadcast
> wired→wireless (respostas vão unicast pro MAC do cliente).
> Customizar pool: `af69d eth0 00.00.00.00.10 00.00.00.00.fe 3600 --raw ...`

---

## 3. Celular: pegar endereço e conversar

No chroot do Nethunter (Kali arm64):

```bash
export PATH=/usr/bin:/bin
export HOME=/root

# 1) pedir endereço (usa a chave automática de ~/.ipv69/key):
/root/bin/af69_raw dhcp wlan0 --server-pub <pubkey_do_servidor_hex>

# saída:
#   dhcp: OFFER 0000000000000010 lease 3600s
#   dhcp: ACK 0000000000000010 — configurado!
#   dhcp: bound src=0000000000000010, ouvindo 5s...
```

Depois de configurado, o endereço é **por-socket**: quem quiser "ter" o
`.10` precisa de um processo bindado nele (o `dhcp` segura 5s). Para
manter o endereço vivo, use o daemon:

```bash
# segura o endereço + cria a interface TAP ip69-0 (chave automática):
sudo /root/bin/ip69d wlan0 --raw --tap ip69-0 \
    --server-pub <pubkey_do_servidor_hex>

# em outro terminal, consultar como `ip addr`:
/root/bin/ip69 addr show
#   1: ip69-0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP
#       inet69 0000000000000010/40 brd ffffffffff scope global dynamic
#          valid_lft 3599sec preferred_lft 3599sec

/root/bin/ip69 lease       # segundos restantes
/root/bin/ip69 renew       # renova (ou SIGUSR1 ao ip69d)
```

Enviar e receber dados (com o endereço do lease como `src` — o módulo
do receptor dropa quem não usa o próprio endereço):

```bash
# enviar dgram (portas em HEX, src = seu endereço):
/root/bin/af69_raw send wlan0 00.00.00.00.10 1 16 "oi" 00.00.00.00.10
#                          ^dst               ^dst_port ^payload  ^src (seu lease)

# ouvir no endereço (filtra só o que é seu):
/root/bin/af69_raw recv wlan0 00.00.00.00.10 10

# ping (echo request → reply do módulo da VM):
/root/bin/af69_raw ping wlan0 00.00.00.00.02 "oi"
```

---

## 4. VM: conversar com o celular

```bash
# na VM, com o módulo carregado:
./af69_test recv 2 00.00.00.00.10 10     # ouvir no endereço do celular (porta 16 dec)
./af69_test send 2 00.00.00.00.10 1 10 "oi celular"   # dst=celular, portas hex
./af69_test ping 2 00.00.00.00.10 "oi"   # echo request

# sem módulo (raw, igual ao celular):
./af69_raw recv eth0 00.00.00.00.10 10
./af69_raw send eth0 00.00.00.00.10 1 10 "oi" 00.00.00.00.02
```

> `ifindex`: `2` = eth0 (confira com `ip -o link`). No af69_test o
> primeiro arg é o **ifindex numérico**; no af69_raw é o **nome** da
> interface.

---

## 5. Segurança (resumo)

| Camada | O que faz | Quem configura |
|---|---|---|
| Allowlist de MAC (`--allow`) | só MACs listados pegam lease | servidor |
| **Ed25519** (`--peer-file`/`--peer`/`--key`/`--server-pub`) | assina DHCP; vazou a privada de um device = só ele cai; sem secret compartilhado | servidor + clientes |
| Binding de lease no módulo (`IPV69_BIND_ADD`) | dgram só de endereço com lease válido e MAC correto; resto dropado | automático (af69d) |

Sem `--peer`/`--peer-file`/`--key` o DHCP fica sem cripto (só allowlist
MAC se passar `--allow`) — ok para lab, não para rede compartilhada.

Detalhes e wire format: `docs/security.md`.

---

## 6. Armadilhas conhecidas

- **PATH do chroot**: sempre `export PATH=/usr/bin:/bin` antes de rodar
  (senão usa `/system/bin` do Android).
- **HOME no chroot**: `export HOME=/root` — o auto-key guarda a chave
  em `~/.ipv69/key`; sem HOME ela vai para um lugar inesperado.
- **Portas são hex**: `recv ... 10` = porta 16 decimal; o frame mostra
  `ports=1/16` em decimal.
- **src no send**: com binding ativo no receptor, mandar dgram com `src`
  que não é seu lease = drop silencioso.
- **Broadcast wired→wireless**: muitos APs filtram; use `--raw` no
  servidor (unicast) ou teste VM↔celular pela mesma porta do roteador.
- **Ethernet padding**: frames curtos chegam com padding (60B mínimo) —
  o módulo já aceita (fix incluído).
- **Módulo não carregado no celular**: kernel 4.19 stock (AF_MAX=45) não
  tem AF_69 — por isso o celular usa `af69_raw` (AF_PACKET, mesmo wire
  format).
- **Módulo em uso no WSL**: `rmmod af69` falha se houver socket AF_69
  aberto — mate os processos (`pkill -f 'build/ip69[d]'`) antes.

---

## 7. Build

```bash
make af69_raw af69_test af69d ipv69-keygen ip69 ip69d   # x64
make -C kernel/af69 KDIR=/home/bacal/wsl-kernel         # módulo (WSL)
# arm64 (celular):
aarch64-linux-gnu-gcc -O2 -static -Iinclude -Ilib/ed25519/include \
    -o af69_raw_arm64 tests/af69_raw.c src/IPv69/parse.c \
    lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c
```

---

## 8. A lib `ed25519` (para outros projetos)

A cripto vive em `lib/ed25519/` **separada do protocolo** — o IPv69
consome a mesma API que você usaria no seu "HTTPS próprio". Nada ali
depende de AF_69, header.h ou do kernel.

```c
#include "ed25519.h"

uint8_t seed[ED25519_SEED_LEN], sk[ED25519_SK_LEN], pk[ED25519_PUB_LEN];
uint8_t sig[ED25519_SIG_LEN];

ed25519_keypair(sk, pk);                          // sk[0..31]=seed, sk[32..63]=pub
ed25519_seed_to_pub(pk, seed);                    // derivar pub de um seed existente
ed25519_sign(sig, msg, msglen, sk);               // sk = seed (deriva a pub interna)
ed25519_verify(msg, msglen, sig, pk) == 0;        // 0 = assinatura válida

// persistência no estilo SSH (~/.ipv69/key, seed hex, modo 0600):
char path[256];
ed25519_keyfile_default_path(path, sizeof(path));
ed25519_keyfile_load_or_create(sk, path);         // 1 = gerou e imprimiu a pub nova
```

Compilar contra a lib (sem Makefile do projeto):

```bash
gcc -O2 -Ilib/ed25519/include -o meu_app meu_app.c \
    lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c
```

Notas:
- Assinatura ~1.7ms (x64) / ~7.4ms (arm64 A53) para mensagens pequenas.
- A privada é o **seed** (32B hex no keyfile); a pub deriva dele.
- `tweetnacl.c` é CC0/domínio público (TweetNaCl 20140427); `ed25519.c`
  é o wrapper com a API limpa (sig separado, buffers independentes).
