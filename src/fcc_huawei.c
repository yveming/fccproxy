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
#include "fcc_huawei.h"

#include <arpa/inet.h>
#include <string.h>

int huawei_is_request(int fmt, ssize_t len)
{
    return fmt == FCC_FMT_HUAWEI_REQ && len >= FCC_PK_LEN_REQ_HUAWEI_MIN;
}

int huawei_is_response(int fmt)
{
    return fmt == FCC_FMT_HUAWEI_RESP;
}

void huawei_save_client_media_port(proxy_session_t *sess,
                                   const uint8_t *buf, ssize_t len)
{
    if (sess->client_media_port || len < FCC_PK_LEN_REQ_HUAWEI_MIN)
        return;

    const fcc_huawei_req_t *req = (const fcc_huawei_req_t *)buf;
    sess->client_media_port = htons(ntohs(req->signal_port) - 1);
}

int huawei_update_server_from_response(const uint8_t *buf, ssize_t len,
                                       proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_RESP_HUAWEI_MIN)
        return 0;

    const fcc_huawei_resp_t *resp = (const fcc_huawei_resp_t *)buf;
    uint16_t type = ntohs(resp->type);

    /* server_ip sits at offset 36
     * response. server_port at offset 30 — present from the most-common
     * (36-byte) response upward. Guard each by actual packet length. */
    int have_server_ip = (len >= FCC_PK_LEN_RESP_HUAWEI) &&
                         resp->server_ip;
    int have_server_port = (len >= FCC_PK_LEN_RESP_HUAWEI) &&
                           resp->server_port;

    if (type == 2)
    {
        /* Huawei type=2 (accepted). Server will send unicast RTP
         * to our media_port. media_sock has never sent anything,
         * so conntrack has no entry and the firewall would drop
         * the inbound RTP. Punching is done by the client's FMT12 path. */
        if (have_server_ip)
            sess->server_addr.sin_addr.s_addr = resp->server_ip;
        if (have_server_port)
            sess->server_media_port = resp->server_port;
        return 0;
    }

    if (type == 3)
    {
        if (have_server_ip)
            sess->server_addr.sin_addr.s_addr = resp->server_ip;
        if (have_server_port)
            sess->server_addr.sin_port = resp->server_port;
        PXY_INFO("Session %d redirect to %s:%u",
                 sess->slot, inet_ntoa(sess->server_addr.sin_addr),
                 ntohs(sess->server_addr.sin_port));
    }

    return 0;
}

ssize_t nat_huawei_request(uint8_t *buf, ssize_t len, proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_REQ_HUAWEI_MIN)
        return -1;

    fcc_huawei_req_t *req = (fcc_huawei_req_t *)buf;
    req->client_ip = g_config.local_addr.s_addr;
    req->signal_port = sess->signal_nport;

    return len;
}

/*
 * Huawei response NAT. Two cases, both rewrite server_ip to the proxy LAN IP
 * (the address the client reaches us on):
 *
 *   type=3 (redirect): replace redirect IP with proxy LAN IP, leave
 *     server_port as 0. The client retries FMT5 to the proxy on the default
 *     signaling port (8027).
 *
 *   type=2 (accepted): replace media server IP with proxy LAN IP and
 *     server_port with the proxy's media socket port, so the client sends its
 *     FMT12 NAT-traversal punch (and the server's RTP returns) to the proxy's
 *     media socket.
 *
 * The real server/redirect IP/port are saved before this NAT, so the proxy can
 * forward FMT12/RTP to the real address.
 *
 * Huawei responses are variable-length (shortest 24, most common 36, longest
 * 44).  Rewrite only fields that are present in the received packet; keep the
 * original length so clients see the same short/long form the server sent.
 */
ssize_t nat_huawei_response(uint8_t *buf, ssize_t len, proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_RESP_HUAWEI_MIN)
        return -1;

    if (len >= FCC_PK_LEN_RESP_HUAWEI)
    {
        fcc_huawei_resp_t *resp = (fcc_huawei_resp_t *)buf;

        if (resp->server_ip)
            resp->server_ip = sess->lan_ip.s_addr;

        if (ntohs(resp->type) == 2 && resp->server_port)
            resp->server_port = sess->client_nport;
    }

    return len;
}

int huawei_is_nat_pkt(const uint8_t *buf, ssize_t len)
{
    if (len < FCC_PK_LEN_NAT_HUAWEI)
        return 0;

    const fcc_huawei_nat_pkt_t *nat = (const fcc_huawei_nat_pkt_t *)buf;
    return (nat->magic0 == 0x00 && nat->magic1 == 0x03);
}