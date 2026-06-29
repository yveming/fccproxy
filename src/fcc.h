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

#ifndef __FCC_H__
#define __FCC_H__

#include <sys/types.h>

#include "fcc_session.h"

#if defined(__GNUC__)
#define FCC_PACKED __attribute__((packed))
#else
#define FCC_PACKED
#endif

/* RTCP common fields */
#define RTCP_PT_RTPFB 205  /* Generic RTP Feedback payload type */

typedef struct FCC_PACKED {
    uint8_t  vpfmt;      /* version/padding/FMT */
    uint8_t  pt;         /* payload type */
    uint16_t length;
    uint32_t sender_ssrc;
    uint32_t media_ssrc;
} fcc_rtcp_fb_hdr_t;

/* Protocol detection and conversion */
int     fcc_get_fmt(const uint8_t *buf);
ssize_t fcc_bridge(uint8_t *out, size_t out_size,
                    const uint8_t *in, ssize_t in_len,
                    proto_type_t from, proto_type_t to,
                    proxy_session_t *sess);

/* Packet handlers */
int handle_packet_from_client(const uint8_t *buf, ssize_t len, int fd,
                              const struct sockaddr_in *src,
                              const struct in_addr *dst_ip);
int handle_packet_from_server(const uint8_t *buf, ssize_t len, int fd);

#endif /* __FCC_H__ */