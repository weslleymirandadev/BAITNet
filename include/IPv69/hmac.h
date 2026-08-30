// hmac.h - HMAC-SHA256 for the IPv69 DHCP69 auth token.

#ifndef IPV69_HMAC_H
#define IPV69_HMAC_H

#include <stdint.h>
#include <stddef.h>

#define IPV69_TOKEN_LEN 8   /* truncated HMAC-SHA256, appended to DHCP msgs */

/* out must hold IPV69_TOKEN_LEN bytes */
void ipv69_hmac(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t out[32]);

#endif
