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

#ifndef __FCC_TELECOM_H__
#define __FCC_TELECOM_H__

#include "fcc.h"
#include <stddef.h>

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t  version;
    uint8_t  reserved13[3];
    uint16_t client_port;
    uint16_t mcast_port;
    uint32_t mcast_ip;
    uint8_t  stbid[16];
} fcc_telecom_req_t;

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t  result;        /* 0x00 success, 0x02 fail  */
    uint8_t  type;          /* 0x01 Join immediately, 0x02 Start unicast, 0x03 Redirect */
    uint16_t signal_port;
    uint16_t media_port;
    uint8_t  reserved18[2]; /* 0x0000 */
    uint32_t server_ip;
    uint32_t valid_time;    /* 3600(s) default for redirect, 0 for accepted */
    uint32_t burst_speed;
    uint32_t sync_speed;
} fcc_telecom_resp_t;

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
} fcc_telecom_sync_t;

typedef struct FCC_PACKED {
    fcc_rtcp_fb_hdr_t rtcp;
    uint8_t  type;        /* 0x00 Huawei Request， 0x01 Telecom Terminate */
    uint8_t  reserved13;  /* 0x00 */
    uint16_t first_seq;   /* First multicast sequence */
} fcc_telecom_term_t;

/* Telecom protocol */
int     telecom_is_request(int fmt, ssize_t len);
int     telecom_is_response(int fmt);
void    telecom_save_client_media_port(proxy_session_t *sess,
                                       const uint8_t *buf, ssize_t len);
int     telecom_update_server_from_response(const uint8_t *buf, ssize_t len,
                                            proxy_session_t *sess);
void    telecom_punch_media_hole(const uint8_t *buf, ssize_t len,
                                 proxy_session_t *sess);
ssize_t nat_telecom_request(uint8_t *buf, ssize_t len, proxy_session_t *sess);
ssize_t nat_telecom_response(uint8_t *buf, ssize_t len, proxy_session_t *sess);

/* Telecom FCC FMT Types */
#define FCC_FMT_TELECOM_REQ  2  /* RTCP Request */
#define FCC_FMT_TELECOM_RESP 3  /* RTCP Response */
#define FCC_FMT_TELECOM_SYN  4  /* RTCP Sync Notification */
#define FCC_FMT_TELECOM_TERM 5  /* RTCP Termination */

/* Packet lengths */
#define FCC_PK_LEN_REQ_TELECOM   (ssize_t)sizeof(fcc_telecom_req_t)
#define FCC_PK_LEN_RESP_TELECOM  (ssize_t)sizeof(fcc_telecom_resp_t)
#define FCC_PK_LEN_SYN_TELECOM   (ssize_t)sizeof(fcc_telecom_sync_t)
#define FCC_PK_LEN_TERM_TELECOM  (ssize_t)sizeof(fcc_telecom_term_t)

#endif /* __FCC_TELECOM_H__ */