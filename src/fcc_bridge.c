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

#include "fccproxy.h"
#include "fcc.h"
#include "fcc_huawei.h"
#include "fcc_telecom.h"

#include <arpa/inet.h>
#include <string.h>

/* ================================================================
 * Helpers
 * ================================================================ */

static void copy_rtcp_ids(fcc_rtcp_fb_hdr_t *dst, const fcc_rtcp_fb_hdr_t *src)
{
    dst->sender_ssrc = src->sender_ssrc;
    dst->media_ssrc = src->media_ssrc;
}

static void set_rtcp_header(fcc_rtcp_fb_hdr_t *hdr, uint8_t fmt, size_t pkt_len)
{
    hdr->vpfmt = 0x80 | fmt;
    hdr->pt = RTCP_PT_RTPFB;
    hdr->length = htons((pkt_len / 4) - 1);
}

/* ================================================================
 * Request conversions
 * ================================================================ */

static ssize_t huawei_req_to_telecom(uint8_t *out, size_t out_size,
                                     const uint8_t *in, ssize_t in_len,
                                     proxy_session_t *sess)
{
    if (in_len < FCC_PK_LEN_REQ_HUAWEI_MIN || out_size < FCC_PK_LEN_REQ_TELECOM)
        return -1;

    const fcc_huawei_req_t *src = (const fcc_huawei_req_t *)in;
    fcc_telecom_req_t *dst = (fcc_telecom_req_t *)out;
    memset(dst, 0, FCC_PK_LEN_REQ_TELECOM);

    set_rtcp_header(&dst->rtcp, FCC_FMT_TELECOM_REQ, FCC_PK_LEN_REQ_TELECOM);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    dst->version = 0x00;    /* version 0x00 */
    dst->mcast_ip = src->mcast_ip;
    dst->mcast_port = htons(5140);  /* No direct mapping from Huawei, default port 5140 */
    dst->client_port = sess->signal_nport;

    return FCC_PK_LEN_REQ_TELECOM;
}

static ssize_t telecom_req_to_huawei(uint8_t *out, size_t out_size,
                                     const uint8_t *in, ssize_t in_len,
                                     proxy_session_t *sess)
{
    if (in_len < FCC_PK_LEN_REQ_TELECOM || out_size < FCC_PK_LEN_REQ_HUAWEI)
        return -1;

    const fcc_telecom_req_t *src = (const fcc_telecom_req_t *)in;
    fcc_huawei_req_t *dst = (fcc_huawei_req_t *)out;
    memset(dst, 0, FCC_PK_LEN_REQ_HUAWEI);

    set_rtcp_header(&dst->rtcp, FCC_FMT_HUAWEI_REQ, FCC_PK_LEN_REQ_HUAWEI);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    dst->type = 0x00;
    dst->reserved13 = 0xf4;
    dst->mcast_ip = src->mcast_ip;
    dst->client_ip = g_config.local_addr.s_addr;
    dst->signal_port = sess->signal_nport;
    dst->flag = htons(0x8000);
    dst->redirect = htonl(0x20000000); /* redirect supported */

    return FCC_PK_LEN_REQ_HUAWEI;
}

/* ================================================================
 * Response conversions
 * ================================================================ */

static ssize_t huawei_resp_to_telecom(uint8_t *out, size_t out_size,
                                      const uint8_t *in, ssize_t in_len,
                                      proxy_session_t *sess)
{
    /* Accept the shortest (24-byte) response; redirect fields are read
     * conditionally based on actual packet length. */
    if (in_len < FCC_PK_LEN_RESP_HUAWEI_MIN || out_size < FCC_PK_LEN_RESP_TELECOM)
        return -1;

    const fcc_huawei_resp_t *src = (const fcc_huawei_resp_t *)in;
    fcc_telecom_resp_t *dst = (fcc_telecom_resp_t *)out;
    memset(dst, 0, FCC_PK_LEN_RESP_TELECOM);

    set_rtcp_header(&dst->rtcp, FCC_FMT_TELECOM_RESP, FCC_PK_LEN_RESP_TELECOM);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    /* Map result: Huawei 0x01 (success) → Telecom 0x00, others pass through */
    dst->result = (src->result == 0x01) ? 0x00 : src->result;

    uint16_t src_type = ntohs(src->type);

    dst->signal_port = htons(g_config.listen_port);
    dst->media_port = sess->client_nport;
    if (src_type == 3)
    {
        /* Redirect: keep type=3 regardless of packet length. The real
         * redirect target was already saved by update_server_from_response;
         * substitute the proxy LAN IP so the client redirects to us. */
        dst->type = 3;
        if (src->server_ip)
            dst->server_ip = sess->lan_ip.s_addr;
        dst->valid_time = htonl(3600);
    }
    else
    {
        /* Accepted (type=2): no redirect, client reaches the proxy media socket */
        dst->type = 2;     
    }

    /* Map speed info */
    dst->burst_speed = htonl(ntohs(src->speed) * 1024);
    dst->sync_speed = dst->burst_speed;

    return FCC_PK_LEN_RESP_TELECOM;
}

static ssize_t telecom_resp_to_huawei(uint8_t *out, size_t out_size,
                                      const uint8_t *in, ssize_t in_len,
                                      proxy_session_t *sess)
{
    if (in_len < FCC_PK_LEN_RESP_TELECOM || out_size < FCC_PK_LEN_RESP_HUAWEI_MAX)
        return -1;

    const fcc_telecom_resp_t *src = (const fcc_telecom_resp_t *)in;
    fcc_huawei_resp_t *dst = (fcc_huawei_resp_t *)out;
    memset(dst, 0, FCC_PK_LEN_RESP_HUAWEI_MAX);
    ssize_t len;

    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    /* Map result: Telecom 0x00 (success) → Huawei 0x01, others pass through */
    dst->result = (src->result == 0x00) ? 0x01 : src->result;

    if (src->type == 3)
    {
        set_rtcp_header(&dst->rtcp, FCC_FMT_HUAWEI_RESP, FCC_PK_LEN_RESP_HUAWEI); 

        dst->type = htons(3);     /* Redirect */
        dst->reserved13 = 0x80;   /* Redirect indicator */
        /* Keep server_port = 0: client retries proxy listen port */
        if  (src->server_ip)
            dst->server_ip = sess->lan_ip.s_addr;

        len = FCC_PK_LEN_RESP_HUAWEI;
    }
    else
    {
        set_rtcp_header(&dst->rtcp, FCC_FMT_HUAWEI_RESP, FCC_PK_LEN_RESP_HUAWEI_MAX);

        dst->type = htons(2);     /* Accepted */
        dst->reserved13 = 0x00;
        dst->nat_flag = 0x30; /* nat needed */
        dst->server_port = sess->client_nport;
        dst->server_ip = sess->lan_ip.s_addr;
        len = FCC_PK_LEN_RESP_HUAWEI_MAX;
    }
    
    /* Map speed: Telecom 32-bit → Huawei 2-byte */
    uint32_t speed_val = ntohl(src->burst_speed) / 1024;
    dst->speed = htons(speed_val & 0xffff);

    return len;
}

/* ================================================================
 * Sync conversions
 *
 *   Huawei sync (FMT 8): rtcp header + 4 reserved bytes = 16 bytes
 *   Telecom sync (FMT 4): rtcp header only = 12 bytes
 * ================================================================ */

static ssize_t huawei_sync_to_telecom(uint8_t *out, size_t out_size,
                                       const uint8_t *in, ssize_t in_len,
                                       proxy_session_t *sess __attribute__((unused)))
{
    if (in_len < FCC_PK_LEN_SYN_HUAWEI || out_size < FCC_PK_LEN_SYN_TELECOM)
        return -1;

    const fcc_huawei_sync_t *src = (const fcc_huawei_sync_t *)in;
    fcc_telecom_sync_t *dst = (fcc_telecom_sync_t *)out;
    memset(dst, 0, FCC_PK_LEN_SYN_TELECOM);

    set_rtcp_header(&dst->rtcp, FCC_FMT_TELECOM_SYN, FCC_PK_LEN_SYN_TELECOM);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    return FCC_PK_LEN_SYN_TELECOM;
}

static ssize_t telecom_sync_to_huawei(uint8_t *out, size_t out_size,
                                       const uint8_t *in, ssize_t in_len,
                                       proxy_session_t *sess __attribute__((unused)))
{
    if (in_len < FCC_PK_LEN_SYN_TELECOM || out_size < FCC_PK_LEN_SYN_HUAWEI)
        return -1;

    const fcc_telecom_sync_t *src = (const fcc_telecom_sync_t *)in;
    fcc_huawei_sync_t *dst = (fcc_huawei_sync_t *)out;
    memset(dst, 0, FCC_PK_LEN_SYN_HUAWEI);

    set_rtcp_header(&dst->rtcp, FCC_FMT_HUAWEI_SYN, FCC_PK_LEN_SYN_HUAWEI);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    return FCC_PK_LEN_SYN_HUAWEI;
}

/* ================================================================
 * Termination conversions
 *
 *   Huawei term (FMT 9): rtcp + status + reserved + first_seq = 16 bytes
 *   Telecom term (FMT 5, sub_type 0x01): rtcp + type + reserved + first_seq = 16 bytes
 *
 *   Note: FMT 5 is shared between Huawei req (sub_type 0x00)
 *   and Telecom term (sub_type 0x01).  The sub_type byte at
 *   offset 12 distinguishes them.
 * ================================================================ */

static ssize_t huawei_term_to_telecom(uint8_t *out, size_t out_size,
                                       const uint8_t *in, ssize_t in_len,
                                       proxy_session_t *sess __attribute__((unused)))
{
    if (in_len < FCC_PK_LEN_TERM_HUAWEI || out_size < FCC_PK_LEN_TERM_TELECOM)
        return -1;

    const fcc_huawei_term_t *src = (const fcc_huawei_term_t *)in;
    fcc_telecom_term_t *dst = (fcc_telecom_term_t *)out;
    memset(dst, 0, FCC_PK_LEN_TERM_TELECOM);

    set_rtcp_header(&dst->rtcp, FCC_FMT_TELECOM_TERM, FCC_PK_LEN_TERM_TELECOM);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    dst->type = 0x01;            /* Telecom Termination sub-type */
    dst->first_seq = src->first_seq;

    return FCC_PK_LEN_TERM_TELECOM;
}

static ssize_t telecom_term_to_huawei(uint8_t *out, size_t out_size,
                                       const uint8_t *in, ssize_t in_len,
                                       proxy_session_t *sess __attribute__((unused)))
{
    if (in_len < FCC_PK_LEN_TERM_TELECOM || out_size < FCC_PK_LEN_TERM_HUAWEI)
        return -1;

    const fcc_telecom_term_t *src = (const fcc_telecom_term_t *)in;
    fcc_huawei_term_t *dst = (fcc_huawei_term_t *)out;
    memset(dst, 0, sizeof(fcc_huawei_term_t));

    set_rtcp_header(&dst->rtcp, FCC_FMT_HUAWEI_TERM, FCC_PK_LEN_TERM_HUAWEI);
    copy_rtcp_ids(&dst->rtcp, &src->rtcp);

    dst->status = 0x01;          /* Success termination */
    dst->first_seq = src->first_seq;

    return FCC_PK_LEN_TERM_HUAWEI;
}

/* ================================================================
 * Unified protocol conversion
 *
 * Dispatches by protocol pair first, then by source FMT.  Same-protocol
 * packets are copied through with only the address/port fields NATed.
 * ================================================================ */

static ssize_t bridge_nat_through(uint8_t *out, size_t out_size,
                                  const uint8_t *in, ssize_t in_len,
                                  proto_type_t proto, int fmt,
                                  proxy_session_t *sess)
{
    if ((size_t)in_len > out_size)
        return -1;

    memcpy(out, in, in_len);

    if (proto == PROTO_HUAWEI)
    {
        switch (fmt)
        {
        case FCC_FMT_HUAWEI_REQ:
            return nat_huawei_request(out, in_len, sess);
        case FCC_FMT_HUAWEI_RESP:
            return nat_huawei_response(out, in_len, sess);
        default:
            return in_len;
        }
    }

    if (proto == PROTO_TELECOM)
    {
        switch (fmt)
        {
        case FCC_FMT_TELECOM_REQ:
            return nat_telecom_request(out, in_len, sess);
        case FCC_FMT_TELECOM_RESP:
            return nat_telecom_response(out, in_len, sess);
        default:
            return in_len;
        }
    }

    return -1;
}

static ssize_t bridge_huawei_to_telecom(uint8_t *out, size_t out_size,
                                        const uint8_t *in, ssize_t in_len,
                                        int fmt, proxy_session_t *sess)
{
    switch (fmt)
    {
    case FCC_FMT_HUAWEI_REQ:
        return huawei_req_to_telecom(out, out_size, in, in_len, sess);
    case FCC_FMT_HUAWEI_RESP:
        return huawei_resp_to_telecom(out, out_size, in, in_len, sess);
    case FCC_FMT_HUAWEI_SYN:
        return huawei_sync_to_telecom(out, out_size, in, in_len, sess);
    case FCC_FMT_HUAWEI_TERM:
        return huawei_term_to_telecom(out, out_size, in, in_len, sess);
    default:
        return -1;
    }
}

static ssize_t bridge_telecom_to_huawei(uint8_t *out, size_t out_size,
                                        const uint8_t *in, ssize_t in_len,
                                        int fmt, proxy_session_t *sess)
{
    switch (fmt)
    {
    case FCC_FMT_TELECOM_REQ:
        return telecom_req_to_huawei(out, out_size, in, in_len, sess);
    case FCC_FMT_TELECOM_RESP:
        return telecom_resp_to_huawei(out, out_size, in, in_len, sess);
    case FCC_FMT_TELECOM_SYN:
        return telecom_sync_to_huawei(out, out_size, in, in_len, sess);
    case FCC_FMT_TELECOM_TERM:
        return telecom_term_to_huawei(out, out_size, in, in_len, sess);
    default:
        return -1;
    }
}

ssize_t fcc_bridge(uint8_t *out, size_t out_size,
                    const uint8_t *in, ssize_t in_len,
                    proto_type_t from, proto_type_t to,
                    proxy_session_t *sess)
{
    if (in_len < (ssize_t)sizeof(fcc_rtcp_fb_hdr_t))
        return -1;

    int fmt = fcc_get_fmt(in);

    if (from == to)
        return bridge_nat_through(out, out_size, in, in_len, to, fmt, sess);

    if (from == PROTO_HUAWEI && to == PROTO_TELECOM)
        return bridge_huawei_to_telecom(out, out_size, in, in_len, fmt, sess);

    if (from == PROTO_TELECOM && to == PROTO_HUAWEI)
        return bridge_telecom_to_huawei(out, out_size, in, in_len, fmt, sess);

    return -1;
}
