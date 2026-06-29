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
 *
 * fccproxy.c — FCC Protocol Proxy (transparent UDP forwarding with NAT)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fccproxy.h"
#include "fcc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

proxy_config_t g_config;

/* ================================================================
 * Daemon initialization
 * ================================================================ */
void init_daemon(void)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "FCCPROXY: fork failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
    {
        fprintf(stderr, "FCCPROXY: setsid failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "FCCPROXY: second fork failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);

    chdir("/");

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        dup2(fd, STDIN_FILENO);
        if (!g_config.debug)
        {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
        }
        if (fd > STDERR_FILENO)
            close(fd);
    }

    umask(0);
}

/* ================================================================
 * Main event loop
 * ================================================================ */
static void handle_packet(int fd, const uint8_t *buf, ssize_t len,
                            const struct sockaddr_in *peer,
                            const struct in_addr *dst_ip)
{
    struct in_addr local_ip_addr;
    if (inet_pton(AF_INET, g_config.local_ip, &local_ip_addr) != 1)
        return;

    if (dst_ip->s_addr != local_ip_addr.s_addr)
        handle_packet_from_client(buf, len, fd, peer, dst_ip);
    else
        handle_packet_from_server(buf, len, fd);
}

static void receive_packet(int fd)
{
    int received = 0;

    for (;;)
    {
        uint8_t buf[UDP_PACKET_BUF_SIZE];
        struct sockaddr_in peer;
        struct iovec iov = {buf, sizeof(buf)};
        uint8_t cmsg_buf[PKTINFO_CMSG_BUF_SIZE];
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &peer;
        msg.msg_namelen = sizeof(peer);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        ssize_t n = recvmsg(fd, &msg, 0);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            PXY_ERR("recvmsg fd=%d failed: %s", fd, strerror(errno));
            break;
        }

        struct in_addr dst_ip = {INADDR_ANY};
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
             cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP &&
                cmsg->cmsg_type == IP_PKTINFO)
            {
                struct in_pktinfo *pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
                dst_ip = pkt->ipi_addr;
            }
        }

        handle_packet(fd, buf, n, &peer, &dst_ip);

        if (++received >= UDP_RECV_BURST_LIMIT)
            break;
    }
}

static void check_interface_ip(time_t now)
{
    static time_t last_ip_check = 0;

    if (!g_config.ifname[0] || now - last_ip_check < IFADDR_CHECK_INTERVAL)
        return;

    char cur_ip[INET_ADDRSTRLEN] = {0};
    if (get_ip_by_interface(g_config.ifname, cur_ip, sizeof(cur_ip)) == 0 &&
        strcmp(cur_ip, g_config.local_ip) != 0)
    {
        PXY_INFO("Interface %s IP changed: %s → %s",
                 g_config.ifname, g_config.local_ip, cur_ip);
        memcpy(g_config.local_ip, cur_ip, sizeof(g_config.local_ip));
        inet_pton(AF_INET, g_config.local_ip, &g_config.local_addr);
    }
    last_ip_check = now;
}

void proxy_loop(void)
{
    struct epoll_event events[EPOLL_MAX_EVENTS];
    time_t last_cleanup = time(NULL);

    while (1)
    {
        int nfds = epoll_wait(g_config.epoll_fd, events,
                              EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (nfds < 0)
        {
            if (errno == EINTR)
                continue;
            PXY_ERR("epoll_wait failed: %s", strerror(errno));
            break;
        }

        time_t now = time(NULL);
        for (int i = 0; i < nfds; i++)
            receive_packet(events[i].data.fd);

        if (now - last_cleanup >= SESSION_CLEANUP_INTERVAL)
        {
            cleanup_expired_sessions(now);
            last_cleanup = now;
        }
        check_interface_ip(now);
    }
}

/* ================================================================
 * Usage & argument parsing
 * ================================================================ */
static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "FCC Protocol Proxy — transparent UDP forwarding with NAT\n"
            "  (auto-detects Huawei or Telecom FCC protocol from client packets)\n"
            "\n"
            "Options:\n"
            "  -p <port>   Listen port for client connections (default: 8027)\n"
            "  -s <IP:PORT> FCC server address (required, e.g. 10.0.0.1:8027)\n"
            "  -i <iface>  Network interface for local IP (optional;\n"
            "                auto-detect via routing table if omitted)\n"
            "  -t          Force server-side protocol to Telecom\n"
            "  -w          Force server-side protocol to Huawei\n"
            "  -v          Verbose: run in foreground, log to stderr\n"
            "  -vv         Very verbose: same as -v, plus per-packet hex dump\n"
            "  -h          Show this help\n"
            "\n"
            "Example:\n"
            "  %s -p 8027 -s 10.0.0.1:8027 -i eth0 -vv\n"
            "  %s -p 8027 -s 172.16.0.1:8027 -v\n"
            "\n",
            prog, prog, prog);
}

static int parse_server_arg(const char *arg)
{
    char *colon = strchr(arg, ':');
    if (!colon)
    {
        fprintf(stderr, "Error: -s requires IP:PORT format (e.g. 10.0.0.1:8027)\n");
        return -1;
    }

    size_t ip_len = (size_t)(colon - arg);
    if (ip_len >= sizeof(g_config.server_ip))
        ip_len = sizeof(g_config.server_ip) - 1;
    memcpy(g_config.server_ip, arg, ip_len);
    g_config.server_ip[ip_len] = '\0';
    g_config.server_port = (uint16_t)atoi(colon + 1);
    return 0;
}

static int parse_args(int argc, char *argv[])
{
    int opt;
    int server_set = 0;

    while ((opt = getopt(argc, argv, "p:s:i:twvh")) != -1)
    {
        switch (opt)
        {
        case 'p':
            g_config.listen_port = (uint16_t)atoi(optarg);
            break;
        case 's':
            if (parse_server_arg(optarg) < 0)
                return -1;
            server_set = 1;
            break;
        case 'i':
            snprintf(g_config.ifname, sizeof(g_config.ifname), "%s", optarg);
            break;
        case 't':
            if (g_config.server_proto != PROTO_UNKNOWN)
            {
                fprintf(stderr, "Error: -t and -w are mutually exclusive\n");
                return -1;
            }
            g_config.server_proto = PROTO_TELECOM;
            break;
        case 'w':
            if (g_config.server_proto != PROTO_UNKNOWN)
            {
                fprintf(stderr, "Error: -t and -w are mutually exclusive\n");
                return -1;
            }
            g_config.server_proto = PROTO_HUAWEI;
            break;
        case 'v':
            if (g_config.daemonize)
                g_config.daemonize = 0;
            else
                g_config.debug = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (!server_set || g_config.server_port == 0)
    {
        fprintf(stderr, "Error: server address (-s IP:PORT) is required\n");
        usage(argv[0]);
        return -1;
    }
    return 0;
}

static int init_local_ip(void)
{
    if (g_config.ifname[0])
    {
        if (get_ip_by_interface(g_config.ifname, g_config.local_ip,
                                sizeof(g_config.local_ip)) < 0)
        {
            fprintf(stderr, "Error: cannot get IP for interface '%s'\n",
                    g_config.ifname);
            return -1;
        }
        PXY_INFO("Interface %s IP: %s", g_config.ifname, g_config.local_ip);
    }
    else if (get_local_ip_for_peer(g_config.server_ip,
                              g_config.local_ip,
                              sizeof(g_config.local_ip)) < 0)
    {
        fprintf(stderr, "Error: cannot determine local IP (-i not given "
                        "and auto-detect to %s failed)\n",
                g_config.server_ip);
        return -1;
    }
    else
        PXY_INFO("Auto-detected local IP: %s", g_config.local_ip);
    inet_pton(AF_INET, g_config.local_ip, &g_config.local_addr);
    return 0;
}

static void init_sessions(void)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        g_config.sessions[i].state = SESS_FREE;
        g_config.sessions[i].server_sock = -1;
        g_config.sessions[i].server_media_sock = -1;
        g_config.sessions[i].client_media_sock = -1;
    }
}

static int init_listen_socket(void)
{
    g_config.listen_fd = create_udp_socket();
    if (g_config.listen_fd < 0)
    {
        PXY_ERR("Failed to create listen socket");
        return -1;
    }
    if (bind_udp_socket(g_config.listen_fd, g_config.listen_port, NULL) < 0)
    {
        close(g_config.listen_fd);
        return -1;
    }

    int pktinfo = 1;
    if (setsockopt(g_config.listen_fd, IPPROTO_IP, IP_PKTINFO,
                   &pktinfo, sizeof(pktinfo)) < 0)
        PXY_ERR("IP_PKTINFO not supported, using -i address for responses");

    PXY_INFO("Listening on UDP port %u", g_config.listen_port);
    return 0;
}

static int init_epoll(void)
{
    g_config.epoll_fd = epoll_create1(0);
    if (g_config.epoll_fd < 0)
    {
        PXY_ERR("epoll_create1 failed: %s", strerror(errno));
        close(g_config.listen_fd);
        return -1;
    }

    if (add_fd_to_epoll(g_config.listen_fd, "listen_fd") < 0)
    {
        close(g_config.listen_fd);
        close(g_config.epoll_fd);
        return -1;
    }
    return 0;
}

static void print_startup_banner(void)
{
    const char *server_proto = "follow-client";
    if (g_config.server_proto == PROTO_TELECOM)
        server_proto = "Telecom";
    else if (g_config.server_proto == PROTO_HUAWEI)
        server_proto = "Huawei";

    PXY_INFO("FCC Proxy started: client=auto-detect, server_proto=%s, server=%s:%u, local=%s, listen=%u",
             server_proto, g_config.server_ip, g_config.server_port,
             g_config.local_ip, g_config.listen_port);

    if (g_config.debug)
    {
        fprintf(stderr, "=== FCC Proxy (DEBUG MODE) ===\n");
        fprintf(stderr, "  Client:    auto-detect (Huawei or Telecom)\n");
        fprintf(stderr, "  Server protocol: %s\n", server_proto);
        fprintf(stderr, "  Listen:    0.0.0.0:%u\n", g_config.listen_port);
        fprintf(stderr, "  Server:    %s:%u\n", g_config.server_ip, g_config.server_port);
        fprintf(stderr, "  Local IP:  %s\n", g_config.local_ip);
        fprintf(stderr, "==============================\n\n");
    }
}

static void cleanup_proxy(void)
{
    close(g_config.listen_fd);
    close(g_config.epoll_fd);
    for (int i = 0; i < MAX_SESSIONS; i++)
        session_free(&g_config.sessions[i]);
    closelog();
}

int main(int argc, char *argv[])
{
    memset(&g_config, 0, sizeof(g_config));
    g_config.listen_port = DEFAULT_LISTEN_PORT;
    g_config.server_proto = PROTO_UNKNOWN;
    g_config.daemonize = 1;

    if (parse_args(argc, argv) < 0)
        return EXIT_FAILURE;
    if (init_local_ip() < 0)
        return EXIT_FAILURE;

    openlog("fccproxy", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    if (g_config.daemonize && !g_config.debug)
        init_daemon();

    signal(SIGPIPE, SIG_IGN);
    init_sessions();

    if (init_listen_socket() < 0 || init_epoll() < 0)
        return EXIT_FAILURE;

    print_startup_banner();
    proxy_loop();
    cleanup_proxy();

    return EXIT_SUCCESS;
}
