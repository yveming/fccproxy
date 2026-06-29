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
#include "fcc_telecom.h"

#include <arpa/inet.h>
#include <string.h>

int telecom_is_request(int fmt, ssize_t len)
{
    return fmt == FCC_FMT_TELECOM_REQ && len >= FCC_PK_LEN_REQ_TELECOM;
}

int telecom_is_response(int fmt)
{
    return fmt == FCC_FMT_TELECOM_RESP;
}

void telecom_save_client_media_port(proxy_session_t *sess,
                                    const uint8_t *buf, ssize_t len)
{
    if (sess->client_media_port || len < FCC_PK_LEN_REQ_TELECOM)
        return;

    const fcc_telecom_req_t *req = (const fcc_telecom_req_t *)buf;
    sess->client_media_port = req->client_port;
}

int telecom_update_server_from_response(const uint8_t *buf, ssize_t len,
                                        proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_RESP_TELECOM)
        return 0;

    const fcc_telecom_resp_t *resp = (const fcc_telecom_resp_t *)buf;
    int learned = 0;

    if (resp->media_port)
    {
        if (!sess->server_media_port)
            learned = 1;
        sess->server_media_port = resp->media_port;
    }

    if (resp->server_ip)
    {
        sess->server_addr.sin_addr.s_addr = resp->server_ip;
        if (resp->signal_port)
            sess->server_addr.sin_port = resp->signal_port;
        PXY_INFO("Session %d redirect to %s:%u",
                 sess->slot, inet_ntoa(*(struct in_addr *)&resp->server_ip),
                 ntohs(sess->server_addr.sin_port));
    }

    return learned;
}

void telecom_punch_media_hole(const uint8_t *buf, ssize_t len,
                              proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_RESP_TELECOM || sess->server_sock < 0)
        return;

    const fcc_telecom_resp_t *resp = (const fcc_telecom_resp_t *)buf;
    struct sockaddr_in hole = sess->server_addr;

    /* Extract the REAL media server IP from the original RESP before NAT.
     * Use signaling server as fallback. */
    if (resp->server_ip)
        hole.sin_addr.s_addr = resp->server_ip;
    if (sess->server_media_port)
        hole.sin_port = sess->server_media_port;
    hole.sin_family = AF_INET;

    uint8_t probe = 0;
    sendto(sess->server_sock, &probe, 1, 0,
           (struct sockaddr *)&hole, sizeof(hole));
    PXY_DBG("  hole punch → %s:%u",
            inet_ntoa(hole.sin_addr), ntohs(hole.sin_port));
}

/*
 * Telecom request NAT: replace fcc_client_media_port
 */
ssize_t nat_telecom_request(uint8_t *buf, ssize_t len, proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_REQ_TELECOM)
        return -1;

    /* Telecom is single-port: the client uses the SAME port for signaling
     * and RTP, so the proxy does too. Advertise signal_nport (server_sock);
     * the server sends unicast RTP back to it, arriving on server_sock. No
     * separate media socket/port is needed for Telecom (unlike Huawei). */
    fcc_telecom_req_t *req = (fcc_telecom_req_t *)buf;
    req->client_port = sess->signal_nport;

    PXY_DBG("NAT(TE-REQ): port=%u", ntohs(sess->signal_nport));
    return len;
}

/*
 * Telecom response NAT: replace new_fcc_ip and ports.
 * Non-response RTCP packets (sync/term) pass through untouched.
 */
ssize_t nat_telecom_response(uint8_t *buf, ssize_t len, proxy_session_t *sess)
{
    if (len < FCC_PK_LEN_RESP_TELECOM)
        return -1;

    fcc_telecom_resp_t *resp = (fcc_telecom_resp_t *)buf;

    resp->signal_port = resp->signal_port ? htons(g_config.listen_port) : 0;
    resp->media_port = resp->media_port ? sess->client_nport : 0;
    resp->server_ip = resp->server_ip ? sess->lan_ip.s_addr : 0;

    PXY_DBG("NAT(TE-RESP): signal=%u media=%u",
            g_config.listen_port, ntohs(sess->client_nport));
    return len;
}
