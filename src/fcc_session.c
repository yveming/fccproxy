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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fccproxy.h"
#include "fcc_session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ================================================================
 * Socket and IP helpers
 * ================================================================ */

int create_udp_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        PXY_ERR("socket() failed: %s", strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(fd);
        return -1;
    }

    /* Increase receive buffer */
    int rcvbuf = UDP_RCVBUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
        PXY_ERR("setsockopt SO_RCVBUF=%d failed: %s", rcvbuf, strerror(errno));

    return fd;
}

int create_serv_sock(void)
{
    return create_udp_socket();
}

/*
 * Get local IP address from a named network interface (e.g. "eth0").
 */
int get_ip_by_interface(const char *ifname, char *out, size_t out_len)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        close(fd);
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    if (!inet_ntop(AF_INET, &sin->sin_addr, out, (socklen_t)out_len))
    {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/*
 * Auto-detect local IP by connecting a UDP socket to the peer address.
 */
int get_local_ip_for_peer(const char *peer_ip, char *out, size_t out_len)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(1); /* dummy */
    if (inet_pton(AF_INET, peer_ip, &peer.sin_addr) != 1)
    {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0)
    {
        close(fd);
        return -1;
    }

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &len) < 0)
    {
        close(fd);
        return -1;
    }

    if (!inet_ntop(AF_INET, &local.sin_addr, out, (socklen_t)out_len))
    {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int bind_udp_socket(int fd, uint16_t port, const char *ip)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (ip && ip[0])
    {
        if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
        {
            PXY_ERR("Invalid IP address: %s", ip);
            return -1;
        }
    }
    else
    {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    int on = 1;
    if ((bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) ||
            (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0))
    {
        PXY_ERR("bind() to %s:%u failed: %s",
                ip ? ip : "0.0.0.0", port, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Bind a pair of adjacent UDP sockets (signal + media).
 * Used when target is Huawei (Huawei server expects paired ports).
 */
int bind_pair_udp_sockets(int *signal_fd, int *media_fd,
                          uint16_t *signal_nport, uint16_t *media_nport,
                          const char *local_ip)
{
    struct sockaddr_in sin;
    int start_port = MEDIA_PORT_MIN;
    int end_port = MEDIA_PORT_MAX;
    int range = end_port - start_port - 1;

    /* Bind to -i interface's IP (WAN), not INADDR_ANY.
     * Kernel 5.4 ignores SO_BINDTODEVICE for INADDR_ANY sockets,
     * and policy routing requires a specific source IP. */
    struct in_addr lip = {INADDR_ANY};
    if (local_ip && local_ip[0])
        inet_pton(AF_INET, local_ip, &lip);

    /* Random start offset to avoid repeated collisions */
    int offset = (int)(time(NULL) % range);
    int port;

    for (int i = 0; i < range; i++)
    {
        port = start_port + ((offset + i) % range);

        /* Try media port first */
        int mfd = create_serv_sock();
        if (mfd < 0)
            continue;

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = lip.s_addr;
        sin.sin_port = htons((uint16_t)port);

        int on = 1;
        if ((bind(mfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) ||
            (setsockopt(mfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0))
        {
            close(mfd);
            continue;
        }

        /* Try signal port = media_port + 1 */
        int sfd = create_serv_sock();
        if (sfd < 0)
        {
            close(mfd);
            continue;
        }

        sin.sin_port = htons((uint16_t)(port + 1));
        if ((bind(sfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) ||
            (setsockopt(sfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0))
        {
            close(mfd);
            close(sfd);
            continue;
        }

        /* Success */
        *signal_fd = sfd;
        *media_fd = mfd;
        *signal_nport = htons((uint16_t)(port + 1));
        *media_nport = htons((uint16_t)port);

        return 0;
    }

    PXY_ERR("Failed to bind paired sockets in range %d-%d", start_port, end_port);
    return -1;
}

/* ================================================================
 * Session management
 * ================================================================ */

proxy_session_t *session_alloc(void)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        if (g_config.sessions[i].state == SESS_FREE)
        {
            proxy_session_t *s = &g_config.sessions[i];
            memset(s, 0, sizeof(*s));
            s->slot = i;
            s->state = SESS_FREE;
            s->created = time(NULL);
            s->last_active = time(NULL);
            s->server_sock = -1;
            s->server_media_sock = -1;
            s->client_media_sock = -1;
            return s;
        }
    }
    return NULL;
}

void session_free(proxy_session_t *s)
{
    if (!s)
        return;

    if (s->server_sock >= 0)
    {
        epoll_ctl(g_config.epoll_fd, EPOLL_CTL_DEL, s->server_sock, NULL);
        close(s->server_sock);
        s->server_sock = -1;
    }
    if (s->server_media_sock >= 0)
    {
        epoll_ctl(g_config.epoll_fd, EPOLL_CTL_DEL, s->server_media_sock, NULL);
        close(s->server_media_sock);
        s->server_media_sock = -1;
    }
    if (s->client_media_sock >= 0)
    {
        epoll_ctl(g_config.epoll_fd, EPOLL_CTL_DEL, s->client_media_sock, NULL);
        close(s->client_media_sock);
        s->client_media_sock = -1;
    }
    s->state = SESS_FREE;
    s->slot = -1;
}

void session_mark_terminating(proxy_session_t *s, time_t now)
{
    if (!s || s->state == SESS_FREE)
        return;

    if (s->state != SESS_TERMINATING)
    {
        PXY_INFO("Session %d terminating, grace=%ds",
                 s->slot, SESSION_TERMINATE_GRACE);
        s->state = SESS_TERMINATING;
    }
    s->term_deadline = now + SESSION_TERMINATE_GRACE;
}

proxy_session_t *session_find_by_client(const struct sockaddr_in *addr)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        proxy_session_t *s = &g_config.sessions[i];
        if (s->state != SESS_FREE &&
            s->client_addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            (s->client_addr.sin_port == addr->sin_port ||
             s->client_media_port == addr->sin_port))
        {
            return s;
        }
    }
    return NULL;
}

proxy_session_t *session_find_by_client_media_port(const struct in_addr *addr,
                                                     uint16_t client_media_port)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        proxy_session_t *s = &g_config.sessions[i];
        if (s->state != SESS_FREE &&
            s->client_addr.sin_addr.s_addr == addr->s_addr &&
            s->client_media_port == client_media_port)
        {
            return s;
        }
    }
    return NULL;
}

proxy_session_t *session_find_by_client_ip(const struct in_addr *addr)
{
    proxy_session_t *sess = NULL;
    time_t latest = 0;

    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        proxy_session_t *s = &g_config.sessions[i];
        if (s->state != SESS_FREE &&
            s->client_addr.sin_addr.s_addr == addr->s_addr &&
            s->last_active > latest)
        {
            latest = s->last_active;
            sess = s;
        }
    }
    return sess;
}

proxy_session_t *session_find_by_server_sock(int fd)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        proxy_session_t *s = &g_config.sessions[i];
        if (s->state != SESS_FREE &&
            (s->server_sock == fd ||
             s->server_media_sock == fd ||
             s->client_media_sock == fd))
        {
            return s;
        }
    }
    return NULL;
}

void cleanup_expired_sessions(time_t now)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        proxy_session_t *s = &g_config.sessions[i];
        if (s->state == SESS_FREE)
            continue;

        if (s->state == SESS_TERMINATING)
        {
            if (s->term_deadline && now >= s->term_deadline)
            {
                PXY_INFO("Session %d termination grace elapsed, freeing", s->slot);
                session_free(s);
            }
            continue;
        }

        if ((now - s->last_active) > SESSION_TIMEOUT)
        {
            PXY_INFO("Session %d expired (idle %lds), freeing",
                     s->slot, (long)(now - s->last_active));
            session_free(s);
        }
    }
}

int add_fd_to_epoll(int fd, const char *name)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;

    if (epoll_ctl(g_config.epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        PXY_ERR("epoll_ctl add %s failed: %s", name, strerror(errno));
        return -1;
    }
    return 0;
}

static int create_client_media_socket(proxy_session_t *sess)
{
    sess->client_media_sock = create_udp_socket();
    if (sess->client_media_sock < 0)
        return -1;

    struct sockaddr_in cm_addr;
    memset(&cm_addr, 0, sizeof(cm_addr));
    cm_addr.sin_family = AF_INET;
    cm_addr.sin_addr.s_addr = INADDR_ANY;
    cm_addr.sin_port = 0;

    if (bind(sess->client_media_sock,
             (struct sockaddr *)&cm_addr, sizeof(cm_addr)) < 0)
    {
        PXY_ERR("bind client_media_sock failed: %s", strerror(errno));
        close(sess->client_media_sock);
        sess->client_media_sock = -1;
        return -1;
    }

    socklen_t sl = sizeof(cm_addr);
    getsockname(sess->client_media_sock, (struct sockaddr *)&cm_addr, &sl);
    sess->client_nport = cm_addr.sin_port;
    return 0;
}

static int create_session_sockets(proxy_session_t *sess)
{
    if (bind_pair_udp_sockets(&sess->server_sock,
                              &sess->server_media_sock,
                              &sess->signal_nport,
                              &sess->media_nport,
                              g_config.local_ip) < 0)
        return -1;

    if (create_client_media_socket(sess) < 0)
        return -1;

    if (add_fd_to_epoll(sess->server_sock, "server_sock") < 0)
        return -1;

    if (sess->server_media_sock >= 0 &&
        add_fd_to_epoll(sess->server_media_sock, "media_sock") < 0)
        return -1;

    if (sess->client_media_sock >= 0 &&
        add_fd_to_epoll(sess->client_media_sock, "client_media_sock") < 0)
        return -1;

    return 0;
}

static int init_session_destination(proxy_session_t *sess,
                                    const struct sockaddr_in *src)
{
    memset(&sess->server_addr, 0, sizeof(sess->server_addr));
    sess->server_addr.sin_family = AF_INET;
    sess->server_addr.sin_port = htons(g_config.server_port);
    if (inet_pton(AF_INET, g_config.server_ip,
                  &sess->server_addr.sin_addr) != 1)
        return -1;

    /* Inherit redirect from an existing session for this client IP. */
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        proxy_session_t *os = &g_config.sessions[i];
        if (os != sess &&
            os->state != SESS_FREE &&
            os->server_addr.sin_addr.s_addr &&
            os->client_addr.sin_addr.s_addr == src->sin_addr.s_addr &&
            (os->server_addr.sin_addr.s_addr != sess->server_addr.sin_addr.s_addr ||
             os->server_addr.sin_port != sess->server_addr.sin_port))
        {
            sess->server_addr = os->server_addr;
            break;
        }
    }

    PXY_DBG(" server dst=%s:%u",
            inet_ntoa(sess->server_addr.sin_addr),
            ntohs(sess->server_addr.sin_port));
    return 0;
}

proxy_session_t *proxy_session_create(const struct sockaddr_in *src,
                                      const struct in_addr *dst_ip,
                                      proto_type_t client_proto,
                                      const char *src_str,
                                      uint16_t src_port)
{
    proxy_session_t *sess = session_alloc();
    if (!sess)
    {
        PXY_ERR("Session table full, dropping request from %s:%u",
                src_str, src_port);
        return NULL;
    }

    sess->client_proto = client_proto;
    sess->server_proto = (g_config.server_proto != PROTO_UNKNOWN) ?
                         g_config.server_proto : client_proto;
    sess->state = SESS_REQUESTED;
    sess->client_addr = *src;
    if (dst_ip->s_addr)
        sess->lan_ip = *dst_ip;
    else
        inet_pton(AF_INET, g_config.local_ip, &sess->lan_ip);

    if (create_session_sockets(sess) < 0 ||
        init_session_destination(sess, src) < 0)
    {
        session_free(sess);
        return NULL;
    }

    PXY_DBG("Session %d created: client=%s:%u client_proto=%d server_proto=%d, signal_fd=%d signal_port=%u media_fd=%d media_port=%u client_media_fd=%d client_media_port=%u",
            sess->slot, src_str, src_port, client_proto, sess->server_proto,
            sess->server_sock, ntohs(sess->signal_nport),
            sess->server_media_sock,
            sess->media_nport ? ntohs(sess->media_nport) : 0,
            sess->client_media_sock, ntohs(sess->client_nport));
    return sess;
}
