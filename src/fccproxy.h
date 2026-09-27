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

#ifndef __FCCPROXY_H__
#define __FCCPROXY_H__

#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>

#include "fcc_session.h"

/* ================================================================
 * Runtime defaults and loop limits
 * ================================================================ */
#define DEFAULT_LISTEN_PORT       8027
#define UDP_PACKET_BUF_SIZE       2048
#define PKTINFO_CMSG_BUF_SIZE     64
#define EPOLL_MAX_EVENTS          128
#define EPOLL_TIMEOUT_MS          2000
#define UDP_RECV_BURST_LIMIT      32
#define IFADDR_CHECK_INTERVAL     10
#define DEBUG_HEX_DUMP_LIMIT      64

/* ================================================================
 * Global proxy configuration
 * ================================================================ */
typedef struct {
    int             debug;
    int             daemonize;

    uint16_t        listen_port;   /* Host byte order */
    char            server_ip[INET_ADDRSTRLEN];
    uint16_t        server_port;   /* Host byte order */
    proto_type_t    server_proto;  /* PROTO_UNKNOWN = follow client */
    struct in_addr  local_addr; /* in_addr of the local ip */
    char            local_ip[INET_ADDRSTRLEN];
    char            ifname[IFNAMSIZ];

    int             listen_fd;
    int             epoll_fd;

    proxy_session_t sessions[MAX_SESSIONS];
} proxy_config_t;

/* ================================================================
 * Logging macros
 *
 * stderr lines carry a "[HH:MM:SS.mmm]" prefix so they can be
 * correlated with packet captures and used to measure zap latency.
 * syslog lines stay prefix-free.
 * ================================================================ */
static inline const char *fcc_log_ts(char *buf, size_t len)
{
    struct timespec ts;
    struct tm tm;
    time_t sec;

    clock_gettime(CLOCK_REALTIME, &ts);
    sec = ts.tv_sec;
    localtime_r(&sec, &tm);
    snprintf(buf, len, "[%02d:%02d:%02d.%03ld] ",
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000L);
    return buf;
}

#define PXY_ERR(fmt, ...)  do { char ts_[32]; \
                                syslog(LOG_ERR,  "FCC_PROXY: " fmt, ##__VA_ARGS__); \
                                if (g_config.debug) fprintf(stderr, "%sFCC_PROXY[ERR]: " fmt "\n", fcc_log_ts(ts_, sizeof(ts_)), ##__VA_ARGS__); } while(0)

#define PXY_INFO(fmt, ...) do { char ts_[32]; \
                                syslog(LOG_INFO,  "FCC_PROXY: " fmt, ##__VA_ARGS__); \
                                if (g_config.debug) fprintf(stderr, "%sFCC_PROXY[INFO]: " fmt "\n", fcc_log_ts(ts_, sizeof(ts_)), ##__VA_ARGS__); } while(0)

#define PXY_DBG(fmt, ...)  do { char ts_[32]; \
                                if (g_config.debug) fprintf(stderr, "%sFCC_PROXY[DBG]: " fmt "\n", fcc_log_ts(ts_, sizeof(ts_)), ##__VA_ARGS__); } while(0)

/* Global config instance */
extern proxy_config_t g_config;

/* ================================================================
 * Main functions
 * ================================================================ */
void proxy_loop(void);
void init_daemon(void);

#endif /* __FCCPROXY_H__ */
