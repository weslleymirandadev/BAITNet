# IPv69 — Arquitetura de rede (bootstrap + gateway)

Como o DHCP69 vira o "pai das conexões" e usuários novos na internet
conseguem seu primeiro IPv69. Define o modelo **hub-and-spoke** com um
servidor central (VPS) e túneis UDP.

## 1. O paradoxo do bootstrap

Para receber um IPv69, o usuário precisa falar com o servidor DHCP69.
Mas o DHCP69 roda em frames L2 (EtherType 0x6969) — que não atravessam
a internet. Logo: **ninguém ganha o primeiro IPv69 sem já ter uma
conexão com o servidor por outro meio**.

Isso vale para todo protocolo novo:

- IPv6 nasceu dentro de túneis sobre IPv4 (6in4, Teredo, 6to4)
- ZeroTier/Tailscale criam a rede virtual dentro de um túnel sobre IP
- Bitcoin faz bootstrap por DNS/seed nodes

**Consequência de design:** a conexão de bootstrap é a internet que já
existe (IP normal) através de um túnel. O IPv69 nasce DENTRO do túnel.
O DHCP69 nunca precisa "saber" que está na internet — para ele, o
DISCOVER chega como um frame normal na interface do gateway.

## 2. Modelo hub-and-spoke

```
        Usuário A (celular)                Usuário B (PC)
        ┌────────────────┐                 ┌────────────────┐
        │ app ip69d      │                 │ app ip69d      │
        │ TAP ip69-0     │                 │ TAP ip69-0     │
        │ túnel UDP/IP ──┼──┐          ┌──┼── túnel UDP/IP │
        └────────────────┘  │          │  └────────────────┘
                            ▼          ▼
                    ┌───────────────────────┐
                    │  VPS na internet       │
                    │  IP público            │
                    │  ┌───────────────────┐ │
                    │  │ ipv69gw (gateway) │ │
                    │  │  listener UDP     │ │
                    │  │  tabela addr↔túnel│ │
                    │  │  switch L2 virtual│ │
                    │  └───────────────────┘ │
                    │  ┌───────────────────┐ │
                    │  │ af69d (DHCP69)    │ │
                    │  │  pool global      │ │
                    │  └───────────────────┘ │
                    └───────────────────────┘
```

O servidor "pai" é uma VPS com IP público rodando:

1. **`ipv69gw` (gateway de túnel)** — recebe frames 0x6969 encapsulados
   em UDP dos clientes; mantém a tabela `endereço 40-bit ↔ túnel`;
   reencaminha frames entre túneis (switch L2 virtual).
2. **`af69d` (DHCP69)** — o mesmo da VM, **sem mudança nenhuma**:
   aloca endereços do pool global, valida chaves Ed25519, registra
   binding addr↔MAC no kernel.
3. **Switch L2 virtual** — quando A manda frame para B, o gateway
   reencaminha pelo túnel do B.

## 3. Fluxo do usuário novo (zero conhecimento prévio)

1. Baixa o app (cliente ip69d + túnel), digita o endereço do servidor
   (ex: `gw.ipv69.net`).
2. O app conecta o túnel UDP ao servidor — aqui ele ainda está usando
   IP normal (a internet de sempre).
3. Dentro do túnel, roda o DHCP69 client → DISCOVER → o servidor aloca
   um IPv69 do pool → **pronto, tem endereço**.
4. O auto-key (`~/.ipv69/key`) já cuida da identidade: o servidor com
   `--learn` registra a pub sozinho e persiste no peer-file.

O usuário nunca vê IP, nunca configura roteamento — o app faz tudo.

## 4. Como A conversa com B

O gateway aprende a tabela `endereço 40-bit ↔ túnel` no próprio tráfego
(como um switch Ethernet aprende MACs). Frame do A para o B:

1. A encapsula o frame 0x6969 num datagrama UDP → envia ao servidor.
2. O gateway desencapsula, lê o dest 40-bit, acha o túnel do B.
3. Reencapsula e envia pelo túnel do B.
4. O binding no kernel continua valendo (o servidor registrou
   addr↔MAC de cada cliente no ACK do DHCP).

Todo tráfego passa pelo servidor — simples, previsível, e é como as
VPNs comerciais começam (ZeroTier, Hamachi, Tailscale DERP).

## 5. Encapsulamento do túnel (wire format)

```
Datagrama UDP: [frame IPv69 completo: eth 14 + header 38 + payload]

UDP dest port: fixa (ex: 6969) — a porta identifica o serviço no
servidor; o endereço IPv69 continua morando no header do frame.
```

Minimalista de propósito (tipo VXLAN sem cabeçalho extra): o frame
IPv69 inteiro dentro de um datagrama UDP. O gateway só precisa ler o
header 0x6969 para decidir o destino.

## 6. O que muda e o que NÃO muda no código

| Componente | Mudança |
|---|---|
| `af69d` (DHCP69) | **Nada** — o DISCOVER chega como frame normal na interface do gateway |
| `af69_raw` / `ip69d` (cliente) | Ganha modo `--remote servidor:porta`: em vez de AF_PACKET na wlan0, manda os frames por UDP |
| `ipv69gw` (novo, servidor) | Listener UDP multi-cliente + tabela addr↔túnel + forwarding (~200 linhas) |
| Encapsulamento | Frame 0x6969 dentro de UDP, porta fixa |
| Cripto do túnel | Identidade Ed25519 autentica o cliente (já existe); criptografar o túnel com secretbox quando o ICSP existir |

Wire format, DHCP, binding, protocolo: **nada muda**. Só aparece um
transporte novo entre cliente e servidor.

## 7. Variações futuras

- **P2P depois do bootstrap**: o servidor apresenta os peers (estilo
  Tailscale/DERP) e os clientes passam a conversar direto via hole
  punching — o servidor vira só coordenador, gastando quase nada de
  banda. Fase 2 natural.
- **Servidor em casa**: port forwarding + DDNS funciona, mas NAT do
  roteador + IP dinâmico = menos estável que VPS.
- **Multi-tenant**: o mesmo gateway roda N redes isoladas (cada uma com
  pool e allowlist próprios) — modelo de assinatura por rede/device.

## 8. Relação com o ICSP

O ICSP (docs/icsp-spec.md) é o transporte stream **dentro** da rede
IPv69. O gateway/túnel é o transporte que **liga a rede IPv69 à
internet**. Os dois são independentes:

- Sem ICSP: dgram (nh=1) funciona pelo gateway normalmente.
- Sem gateway: ICSP funciona no L2 local (veth, Wi-Fi, bridge).
- Juntos: stream confiável e criptografado entre usuários na internet.
