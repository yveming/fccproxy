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

#ifndef __FCC_SESSION_H__
#define __FCC_SESSION_H__

#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

/* ================================================================
 * Protocol type (auto-detected from incoming packets)
 * ================================================================ */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_TELECOM,
    PROTO_HUAWEI
} proto_type_t;

/* ================================================================
 * Proxy session state
 * ================================================================ */
typedef enum {
    SESS_FREE = 0,
    SESS_REQUESTED,      /* Request forwarded, waiting for server response */
    SESS_TERMINATING     /* TERM forwarded, waiting briefly for repeats */
} session_state_t;

/* ================================================================
 * Proxy session
 * ================================================================ */
typedef struct {
    int              slot;              /* Index in session table */
    session_state_t  state;
    proto_type_t     client_proto;
    proto_type_t     server_proto;

    /* Client identity */
    struct sockaddr_in client_addr;
    struct in_addr    lan_ip;     /* local IP the client reached us on */
    uint16_t client_media_port;        /* client's media port (net): Telecom=REQ off16, Huawei=signal-1/NAT-learned */

    /* client-side sockets */
    int  client_media_sock;  /* Media socket (client side, lan_ip) */

    /* Server-side sockets */
    int  server_sock;        /* Signal socket */
    int  server_media_sock;  /* Media socket (server side, INADDR_ANY) */

    /* Local port assignments (network byte order) */
    uint16_t signal_nport; /* server side signal port */
    uint16_t media_nport; /* server side media port */
    uint16_t client_nport; /* proxy's client media port (net order) */

    /* Timestamps */
    time_t created;
    time_t last_active;
    time_t term_deadline;

    /* Saved server address for response routing */
    struct sockaddr_in server_addr;
    uint16_t server_media_port;   /* real server media port (network order) */
} proxy_session_t;

#define MAX_SESSIONS             64
#define SESSION_TIMEOUT          3   /* seconds */
#define SESSION_TERMINATE_GRACE  1   /* seconds */
#define SESSION_CLEANUP_INTERVAL 2   /* seconds */
#define UDP_RCVBUF_SIZE          (512 * 1024)
#define MEDIA_PORT_MIN           20000
#define MEDIA_PORT_MAX           60000

/* ================================================================
 * Socket and IP helpers
 * ================================================================ */
int     add_fd_to_epoll(int fd, const char *name);
int     create_udp_socket(void);
int     create_serv_sock(void);
int     bind_udp_socket(int fd, uint16_t port, const char *ip);
int     bind_pair_udp_sockets(int *signal_fd, int *media_fd,
                              uint16_t *signal_nport, uint16_t *media_nport,
                              const char *local_ip);
int     get_ip_by_interface(const char *ifname, char *out, size_t out_len);
int     get_local_ip_for_peer(const char *peer_ip, char *out, size_t out_len);

/* ================================================================
 * Session management
 * ================================================================ */
proxy_session_t *proxy_session_create(const struct sockaddr_in *src,
                                      const struct in_addr *dst_ip,
                                      proto_type_t client_proto,
                                      const char *src_str,
                                      uint16_t src_port);
proxy_session_t *session_alloc(void);
void             session_free(proxy_session_t *s);
void             session_mark_terminating(proxy_session_t *s, time_t now);
proxy_session_t *session_find_by_client(const struct sockaddr_in *addr);
proxy_session_t *session_find_by_client_ip(const struct in_addr *addr);
proxy_session_t *session_find_by_client_media_port(const struct in_addr *addr,
                                                     uint16_t client_media_port);
proxy_session_t *session_find_by_server_sock(int fd);
void             cleanup_expired_sessions(time_t now);

#endif /* __FCC_SESSION_H__ */
