#ifndef IPV69_PARSE_H
#define IPV69_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include "header.h"

/* retorna 0 se valido, ou codigo de erro:
   1 frame curto, 2 ethertype errado, 4 versao errada,
   5 payload_len inconsistente, 6 next_header desconhecido */
int parse_ipv69_frame(const uint8_t *frame, size_t len);

/* imprime os campos do header em hex, um por linha */
void print_ipv69_fields(const struct ipv69_header *h);

/* imprime src_port, dst_port e os dados do datagrama 253 como texto */
void print_dgram253(const uint8_t *payload, size_t len);

/* imprime payload generico: texto (bytes nao imprimiveis viram '.') + hex */
void print_payload(const uint8_t *payload, size_t len);

#endif
