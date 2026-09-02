#ifndef IPV69_AF_H
#define IPV69_AF_H

#include <stdint.h>

/* next_header values (protocol of the payload) */
#define IPV69_NEXT_CONTROL   0
#define IPV69_NEXT_DGRAM     1
#define IPV69_NEXT_STREAM    2       /* reserved (future SCTP-derived transport) */

/* control payload[0] types (next_header 0) */
#define IPV69_CTRL_ND_REQUEST    1
#define IPV69_CTRL_ND_REPLY      2
#define IPV69_CTRL_ECHO_REQUEST  3
#define IPV69_CTRL_ECHO_REPLY    4
#define IPV69_CTRL_UNREACHABLE   5
#define IPV69_CTRL_TIME_EXCEEDED 6
#define IPV69_CTRL_DHCP_DISCOVER 7
#define IPV69_CTRL_DHCP_OFFER    8
#define IPV69_CTRL_DHCP_REQUEST  9
#define IPV69_CTRL_DHCP_ACK      10
#define IPV69_CTRL_DHCP_RELEASE  11
/* gateway mesh (federated gateways on the same L2) */
#define IPV69_CTRL_GW_ANN        12  /* announce: [udp_port 2] */
#define IPV69_CTRL_GW_Q          13  /* query:    [addr 5] */
#define IPV69_CTRL_GW_R          14  /* reply:    [addr 5][ip4 4][port 2] */
/* gateway federation (links): host routes between gateways */
#define IPV69_CTRL_GW_ROUTE      15  /* [addr 5][prefix 1][ip4 4][port 2] */
/* hole-punch introduction: "someone asked where you are" */
#define IPV69_CTRL_GW_CALL       16  /* [addr 5][ip4 4][port 2] */

/* DHCP69 addressing (see docs/dhcp69-spec.md) */
#define IPV69_SERVER_ADDR        1       /* 00.00.00.00.01 */
#define IPV69_DHCP_POOL_START    0x10    /* 00.00.00.00.10 */
#define IPV69_DHCP_POOL_END      0xfe    /* 00.00.00.00.fe */
#define IPV69_DHCP_LEASE_DEFAULT 3600

#endif
