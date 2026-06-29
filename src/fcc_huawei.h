/*
 * Copyright (C) 2026 ming
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __FCC_HUAWEI_H__
#define __FCC_HUAWEI_H__

#include "fcc.h"
#include <stddef.h>

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t  type;        /* 0x00 Huawei Request， 0x01 Telecom Terminate */
    uint8_t  reserved13;  /* 0xf4 */
    uint16_t mcast_seq;
    uint32_t mcast_ip;
    uint32_t client_ip;
    uint16_t signal_port;
    uint16_t flag;        /* 0x8000 */
    uint32_t redirect;    /* 0x20000000 or none */
} fcc_huawei_req_t;

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t  result;        /* 0x01 success, 0x02 fail */
    uint8_t  reserved13;    /* 0x80 redirect, 0x00 accepted */
    uint16_t type;          /* 0x03 redirect, 0x02 accepted */
    uint16_t first_seq;
    uint16_t reserved18; /* 0000 */
    uint16_t speed;       /* speed in network byte order */
    uint16_t reserved22; /* 0000 */
    /* Fields below absent in the shortest (24-byte) response */
    uint8_t  nat_flag;
    uint8_t  reserved25;
    uint16_t server_port;
    uint32_t session_id;
    uint32_t server_ip;
    /* Fields below absent in the most-common (36-byte) response */
    uint32_t reserved36;
} fcc_huawei_resp_t;

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t reserved12[4];
} fcc_huawei_sync_t;

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t  status;      /* 0x01 success, 0x02 fail */
    uint8_t  reserved13;  /* 0x00 */
    uint16_t first_seq;   /* First multicast sequence */
} fcc_huawei_term_t;

typedef struct FCC_PACKED {
    uint8_t magic0;
    uint8_t magic1;
    uint8_t reserved[2];
} fcc_huawei_nat_pkt_t;

/* Huawei protocol */
int     huawei_is_request(int fmt, ssize_t len);
int     huawei_is_response(int fmt);
int     huawei_is_nat_pkt(const uint8_t *buf, ssize_t len);
void    huawei_save_client_media_port(proxy_session_t *sess,
                                      const uint8_t *buf, ssize_t len);
int     huawei_update_server_from_response(const uint8_t *buf, ssize_t len,
                                           proxy_session_t *sess);
ssize_t nat_huawei_request(uint8_t *buf, ssize_t len, proxy_session_t *sess);
ssize_t nat_huawei_response(uint8_t *buf, ssize_t len, proxy_session_t *sess);

/* Huawei FCC FMT Types */
#define FCC_FMT_HUAWEI_REQ  5   /* RTCP Request */
#define FCC_FMT_HUAWEI_RESP 6   /* RTCP Response */
#define FCC_FMT_HUAWEI_SYN  8   /* RTCP Sync Notification */
#define FCC_FMT_HUAWEI_TERM 9   /* RTCP Termination */

#define FCC_PK_LEN_REQ_HUAWEI_MIN  (ssize_t)offsetof(fcc_huawei_req_t, redirect) /* shortest request (no redirect) */
#define FCC_PK_LEN_REQ_HUAWEI      (ssize_t)sizeof(fcc_huawei_req_t) /* longest request = sizeof(fcc_huawei_req_t) */
#define FCC_PK_LEN_RESP_HUAWEI_MIN (ssize_t)offsetof(fcc_huawei_resp_t, nat_flag) /* shortest response */
#define FCC_PK_LEN_RESP_HUAWEI     (ssize_t)offsetof(fcc_huawei_resp_t, reserved36) /* most common response */
/* longest response = sizeof(fcc_huawei_resp_t); struct is built for the longest packet */
#define FCC_PK_LEN_RESP_HUAWEI_MAX (ssize_t)sizeof(fcc_huawei_resp_t)
#define FCC_PK_LEN_NAT_HUAWEI      (ssize_t)sizeof(fcc_huawei_nat_pkt_t)
#define FCC_PK_LEN_SYN_HUAWEI      (ssize_t)sizeof(fcc_huawei_sync_t)
#define FCC_PK_LEN_TERM_HUAWEI     (ssize_t)sizeof(fcc_huawei_term_t)

#endif /* __FCC_HUAWEI_H__ */