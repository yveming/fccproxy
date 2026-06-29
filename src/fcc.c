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
#include <errno.h>
#include <string.h>
#include <unistd.h>

static int is_rtcp_fcc(const uint8_t *buf, ssize_t len)
{
    if (len < (ssize_t)sizeof(fcc_rtcp_fb_hdr_t))
        return 0;

    const fcc_rtcp_fb_hdr_t *rtcp = (const fcc_rtcp_fb_hdr_t *)buf;
    return ((rtcp->vpfmt & 0xC0) == 0x80) && (rtcp->pt == RTCP_PT_RTPFB);
}

int fcc_get_fmt(const uint8_t *buf)
{
    const fcc_rtcp_fb_hdr_t *rtcp = (const fcc_rtcp_fb_hdr_t *)buf;
    return rtcp->vpfmt & 0x1F;
}

static proto_type_t fcc_detect_proto(const uint8_t *buf, ssize_t len)
{
    if (!is_rtcp_fcc(buf, len))
        return PROTO_UNKNOWN;

    int fmt = fcc_get_fmt(buf);
    switch (fmt)
    {
    case FCC_FMT_TELECOM_REQ:
    case FCC_FMT_TELECOM_RESP:
    case FCC_FMT_TELECOM_SYN:
        return PROTO_TELECOM;
    /* FMT 5 — shared by HUAWEI_REQ.
     * Sub-type byte immediately follows the
     * RTCP feedback header is not reliable.
     */
    case FCC_FMT_TELECOM_TERM: 
        if (len == FCC_PK_LEN_TERM_TELECOM)
            return PROTO_TELECOM;
        else if (len >= FCC_PK_LEN_REQ_HUAWEI_MIN)
            return PROTO_HUAWEI;
        else
            return PROTO_UNKNOWN;
    case FCC_FMT_HUAWEI_RESP:
    case FCC_FMT_HUAWEI_SYN:
    case FCC_FMT_HUAWEI_TERM:
        return PROTO_HUAWEI;
    default:
        return PROTO_UNKNOWN;
    }
}

static int is_proper_request(proto_type_t proto, int fmt, ssize_t len)
{
    return (proto == PROTO_HUAWEI && huawei_is_request(fmt, len)) ||
           (proto == PROTO_TELECOM && telecom_is_request(fmt, len));
}

static int is_term_pkt(proto_type_t proto, int fmt, ssize_t len)
{
    if (proto == PROTO_TELECOM && fmt == FCC_FMT_TELECOM_TERM &&
        len == FCC_PK_LEN_TERM_TELECOM)
        return 1;
    if (proto == PROTO_HUAWEI && fmt == FCC_FMT_HUAWEI_TERM)
        return 1;
    return 0;
}

static ssize_t sendto_reliable(int fd, const void *buf, size_t len, int flags,
                                const struct sockaddr *addr, socklen_t addr_len)
{
    ssize_t sent = sendto(fd, buf, len, flags, addr, addr_len);
    if (sent >= 0)
        return sent;

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
        return 0;
    return sent;
}

static void print_hex(const char *label, const uint8_t *data, ssize_t len)
{
    if (!g_config.debug)
        return;
    fprintf(stderr, "  %s [%zd bytes]: ", label, len);
    for (ssize_t i = 0; i < len && i < DEBUG_HEX_DUMP_LIMIT; i++)
    {
        fprintf(stderr, "%02x ", data[i]);
    }
    if (len > DEBUG_HEX_DUMP_LIMIT)
        fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

static void save_client_media_port(proxy_session_t *sess, proto_type_t proto,
                                   const uint8_t *buf, ssize_t len)
{
    if (proto == PROTO_TELECOM)
        telecom_save_client_media_port(sess, buf, len);
    else if (proto == PROTO_HUAWEI)
        huawei_save_client_media_port(sess, buf, len);
}

static int update_server_from_response(const uint8_t *buf, ssize_t len,
                                       proto_type_t proto,
                                       proxy_session_t *sess)
{
    int fmt = fcc_get_fmt(buf);
    int is_resp = (proto == PROTO_HUAWEI && huawei_is_response(fmt)) ||
                  (proto == PROTO_TELECOM && telecom_is_response(fmt));

    if (!is_resp)
        return 0;

    if (proto == PROTO_TELECOM)
        return telecom_update_server_from_response(buf, len, sess);

    huawei_update_server_from_response(buf, len, sess);
    return 0;
}

static int handle_huawei_nat_from_client(const uint8_t *buf, ssize_t len,
                                         const struct sockaddr_in *src)
{
    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr, src_str, sizeof(src_str));
    uint16_t src_port = ntohs(src->sin_port);

    print_hex("CLIENT → PROXY", buf, len);
    PXY_DBG("RX NAT pkt from client %s:%u", src_str, src_port);

    proxy_session_t *sess = session_find_by_client(src);
    if (!sess)
        sess = session_find_by_client_ip(&src->sin_addr);

    if (sess && sess->server_sock >= 0)
    {
        if (sess->client_proto == PROTO_HUAWEI &&
            sess->client_media_port != src->sin_port)
        {
            PXY_DBG("  Huawei client media port learned: %u → %u",
                    ntohs(sess->client_media_port), src_port);
            sess->client_media_port = src->sin_port;
        }

        if (sess->state != SESS_TERMINATING)
            sess->last_active = time(NULL);

        if (sess->server_proto != PROTO_HUAWEI)
            return 0;

        struct sockaddr_in dst = sess->server_addr;
        int send_fd = sess->server_media_sock;
        if (sess->server_media_port)
            dst.sin_port = sess->server_media_port;
        if (send_fd < 0)
            send_fd = sess->server_sock;

        sendto_reliable(send_fd, buf, len, 0,
                        (struct sockaddr *)&dst, sizeof(dst));
        PXY_DBG("  → forwarded NAT pkt to server %s:%u fd=%d",
                inet_ntoa(dst.sin_addr), ntohs(dst.sin_port), send_fd);
    }
    return 0;
}

static int handle_rtcp_from_client(const uint8_t *buf, ssize_t len,
                                   const struct sockaddr_in *src,
                                   const struct in_addr *dst_ip)
{
    int fmt = fcc_get_fmt(buf);
    proto_type_t proto = fcc_detect_proto(buf, len);

    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr, src_str, sizeof(src_str));
    uint16_t src_port = ntohs(src->sin_port);

    PXY_DBG("RX RTCP FMT=%d proto=%d from client %s:%u", fmt, proto, src_str, src_port);
    print_hex("CLIENT → PROXY", buf, len);

    proxy_session_t *sess = session_find_by_client(src);
    if (!sess)
    {
        if (!is_proper_request(proto, fmt, len))
        {
            PXY_DBG("RX RTCP FMT=%d len=%zd from %s:%u: no session, dropping",
                    fmt, len, src_str, src_port);
            return 0;
        }

        /* NAT rebinding: same client may send a second REQUEST from a
         * different source port but advertising the same client_media_port.
         * Reuse the existing session instead of creating a duplicate. */
        uint16_t adv_media_port = 0;
        if (proto == PROTO_TELECOM && len >= FCC_PK_LEN_REQ_TELECOM)
        {
            const fcc_telecom_req_t *req = (const fcc_telecom_req_t *)buf;
            adv_media_port = req->client_port;
        }
        else if (proto == PROTO_HUAWEI && len >= FCC_PK_LEN_REQ_HUAWEI_MIN)
        {
            adv_media_port = htons(ntohs(src->sin_port) - 1);
        }

        if (adv_media_port)
            sess = session_find_by_client_media_port(&src->sin_addr,
                                                     adv_media_port);
        if (sess)
        {
            PXY_DBG("REQ from new port %u reuses session %d (port %u)",
                    src_port, sess->slot, ntohs(adv_media_port));
            sess->client_addr.sin_port = src->sin_port;
        }
        else
        {
            sess = proxy_session_create(src, dst_ip, proto, src_str, src_port);
            if (!sess)
                return -1;
        }
    }

    save_client_media_port(sess, proto, buf, len);
    
    if (sess->state != SESS_TERMINATING)
        sess->last_active = time(NULL);

    uint8_t server_buf[64];
    ssize_t server_len = fcc_bridge(server_buf, sizeof(server_buf),
                                     buf, len,
                                     proto, sess->server_proto,
                                     sess);
    if (server_len <= 0)
        return 0;

    print_hex("PROXY → SERVER", server_buf, server_len);
    PXY_DBG("  dst=%s:%u fd=%d",
            inet_ntoa(sess->server_addr.sin_addr),
            ntohs(sess->server_addr.sin_port),
            sess->server_sock);
    if (sendto_reliable(sess->server_sock, server_buf, server_len, 0,
                        (struct sockaddr *)&sess->server_addr,
                        sizeof(sess->server_addr)) < 0)
        PXY_ERR("sendto server failed: %s", strerror(errno));

    if (is_term_pkt(proto, fmt, len))
    {
        PXY_INFO("TERM received from client %s:%u, terminating session %d",
                 src_str, src_port, sess->slot);
        session_mark_terminating(sess, time(NULL));
    }

    return 0;
}

static int handle_media_from_client(const uint8_t *buf, ssize_t len,
                                    const struct sockaddr_in *src)
{
    static int rtp_dbg_count = 0;
    proxy_session_t *sess = session_find_by_client(src);
    if (!sess)
        sess = session_find_by_client_ip(&src->sin_addr);

    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr, src_str, sizeof(src_str));
    uint16_t src_port = ntohs(src->sin_port);

    if (sess && sess->server_sock >= 0)
    {
        struct sockaddr_in dst = sess->server_addr;
        if (sess->server_media_port)
            dst.sin_port = sess->server_media_port; /* keepalive → media port */
        if (g_config.debug && ++rtp_dbg_count <= 5)
            fprintf(stderr, "FCCPROXY[DBG]: RX %s from client %s:%u "
                            "→ forwarding to server %s:%u\n",
                    len <= 1 ? "keepalive" : "RTP",
                    src_str, src_port,
                    inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
        if (sess->state != SESS_TERMINATING)
            sess->last_active = time(NULL);
        sendto_reliable(sess->server_sock, buf, len, 0,
                        (struct sockaddr *)&dst, sizeof(dst));
    }
    else if (g_config.debug && ++rtp_dbg_count <= 3)
    {
        fprintf(stderr, "FCCPROXY[DBG]: RX RTP from unknown client %s:%u, dropping\n",
                src_str, src_port);
    }

    return 0;
}

int handle_packet_from_client(const uint8_t *buf, ssize_t len, int fd,
                              const struct sockaddr_in *src,
                              const struct in_addr *dst_ip)
{
    if (huawei_is_nat_pkt(buf, len))
        return handle_huawei_nat_from_client(buf, len, src);

    if (fd == g_config.listen_fd)
        return handle_rtcp_from_client(buf, len, src, dst_ip);

    return handle_media_from_client(buf, len, src);
}

static int handle_rtcp_from_server(const uint8_t *buf, ssize_t len,
                                   proxy_session_t *sess)
{
    int server_fmt = fcc_get_fmt(buf);
    proto_type_t server_proto = sess->server_proto;

    char client_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sess->client_addr.sin_addr, client_str, sizeof(client_str));    
    PXY_DBG("RX RTCP FMT=%d server_proto=%d client_proto=%d from server (client=%s:%u)",
            server_fmt, server_proto, sess->client_proto,
            client_str, ntohs(sess->client_addr.sin_port));
    print_hex("SERVER → PROXY", buf, len);

    uint8_t server_buf[64];
    if (len > (ssize_t)sizeof(server_buf))
        return 0;

    memcpy(server_buf, buf, len);
    int media_port_learned = update_server_from_response(server_buf, len,
                                                        server_proto, sess);

    uint8_t client_buf[64];
    ssize_t client_len = fcc_bridge(client_buf, sizeof(client_buf),
                                     server_buf, len,
                                     server_proto,
                                     sess->client_proto,
                                     sess);
    if (client_len <= 0)
        return 0;

    print_hex("PROXY → CLIENT", client_buf, client_len);

    struct sockaddr_in to = sess->client_addr;
    PXY_DBG("  dst=%s:%u", client_str, ntohs(to.sin_port));

    if (sendto_reliable(g_config.listen_fd, client_buf, client_len, 0,
                        (struct sockaddr *)&to, sizeof(to)) < 0)
        PXY_ERR("sendto client failed: %s", strerror(errno));

    if (server_proto == PROTO_TELECOM &&
        telecom_is_response(server_fmt) && media_port_learned)
        telecom_punch_media_hole(buf, len, sess);

    return 0;
}

static int handle_media_from_server(const uint8_t *buf, ssize_t len,
                                    proxy_session_t *sess)
{
    static int rtp_dbg_count = 0;

    if (g_config.debug && ++rtp_dbg_count <= 3)
    {
        char client_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sess->client_addr.sin_addr, client_str, sizeof(client_str));    
        fprintf(stderr, "FCCPROXY[DBG]: RX RTP from server"
                        " → forwarding to client %s:%u\n", client_str,
                ntohs(sess->client_media_port ? sess->client_media_port
                                         : sess->client_addr.sin_port));
    }

    int send_fd = (sess->client_media_sock >= 0)
                      ? sess->client_media_sock
                      : g_config.listen_fd;

    struct sockaddr_in to = sess->client_addr;
    if (sess->client_media_port)
        to.sin_port = sess->client_media_port;

    if (sendto_reliable(send_fd, buf, len, 0,
                        (struct sockaddr *)&to, sizeof(to)) < 0)
        PXY_ERR("sendto client (RTP) failed: %s", strerror(errno));

    return 0;
}

int handle_packet_from_server(const uint8_t *buf, ssize_t len, int fd)
{
    proxy_session_t *sess = session_find_by_server_sock(fd);
    if (!sess)
    {
        PXY_DBG("RX from unknown server socket fd=%d, dropping", fd);
        return 0;
    }

    if ((fd == sess->server_sock) &&  is_rtcp_fcc(buf, len))
        return handle_rtcp_from_server(buf, len, sess);

    return handle_media_from_server(buf, len, sess);
}