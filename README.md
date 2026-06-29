# fccproxy — FCC Protocol Proxy

**fccproxy** is a transparent UDP proxy that bridges the FCC (Fusion Communication Center) protocol between **Huawei** and **China Telecom** variants. It auto-detects the client protocol, translates packets on-the-fly, and performs NAT rewriting so both sides believe they are communicating directly.

## Features

- **Bidirectional protocol conversion** between Huawei and Telecom FCC signaling (request, response, sync, termination)
- **Same-protocol NAT passthrough** with address/port rewriting
- **Auto-detection** of client protocol from RTCP feedback header FMT values
- **Dynamic local IP detection** — by named interface or via routing table lookup
- **Interface IP monitoring** — adapts when the network interface IP changes
- **Session management** — up to 64 concurrent sessions with configurable timeouts
- **NAT rebinding support** — handles clients that change source port mid-session
- **Media hole-punching** for Telecom-side firewall conntrack
- **Paired port binding** for Huawei sessions (signal + media on adjacent ports)
- **Server redirect inheritance** — redirects propagate to all subsequent sessions from the same client
- **epoll-based I/O** with burst-limited receive
- **Daemonization** with double-fork and syslog integration
- **Zero external dependencies** — only Linux kernel and standard C library

## Architecture

```
┌──────────────────┐     UDP/RTCP/RTP     ┌──────────────────────────┐     UDP/RTCP/RTP     ┌──────────────────┐
│   FCC Client     │ ◄──────────────────► │        fccproxy          │ ◄──────────────────► │   FCC Server     │
│ (Huawei/Telecom) │                      │  (Huawei ↔ Telecom)      │                      │ (Huawei/Telecom) │
└──────────────────┘                      └──────────────────────────┘                      └──────────────────┘
```

The proxy listens on a UDP port, receives client packets, detects the protocol variant, converts between formats via `fcc_bridge()`, and forwards to the upstream server. Return traffic is converted back and sent to the client.

## Project Structure

```
├── Makefile           Build system
├── src/
│   ├── fccproxy.c     Entry point: main(), arg parsing, event loop, daemon
│   ├── fccproxy.h     Main header: config struct, logging macros, defaults
│   ├── fcc.c          Protocol detection, packet dispatch, NAT + bridging
│   ├── fcc.h          Common FCC protocol definitions
│   ├── fcc_session.c  Session create/find/free, socket helpers
│   ├── fcc_session.h  Session struct, socket helpers, session management API
│   ├── fcc_bridge.c   Protocol conversion functions (Huawei ↔ Telecom)
│   ├── fcc_huawei.c   Huawei-specific logic
│   ├── fcc_huawei.h   Huawei protocol packet structs
│   ├── fcc_telecom.c  Telecom-specific logic
│   └── fcc_telecom.h  Telecom protocol packet structs
└── build/             Object file output directory
```

## Build

### Dependencies

- C compiler (GCC or compatible)
- Linux kernel headers
- make

### Commands

```bash
# Native build
make

# Cross-compile for ARM64
make CROSS_COMPILE=aarch64-linux-gnu-
# or
make CC=aarch64-linux-gnu-gcc
# or
make arm64

# Install to a staging directory
make install DESTDIR=/tmp/pkg PREFIX=/usr

# Clean
make clean
```

### Build variables

| Variable       | Default               | Description                          |
|----------------|-----------------------|--------------------------------------|
| `CC`           | `gcc`                 | C compiler                           |
| `CROSS_COMPILE`| (empty)               | Toolchain prefix for cross-compilation|
| `CFLAGS`       | `-Wall -Wextra -O2`   | Compiler flags                       |
| `PREFIX`       | `/usr/local`          | Installation prefix                  |
| `SBINDIR`      | `$(PREFIX)/sbin`      | Target directory for installation    |

## Usage

```
fccproxy [options]

Options:
  -p <port>    Listen port for client connections (default: 8027)
  -s <IP:PORT> FCC server address (required, e.g. 10.0.0.1:8027)
  -i <iface>   Network interface for local IP (optional;
                 auto-detects via routing table if omitted)
  -t           Force server-side protocol to Telecom
  -w           Force server-side protocol to Huawei
  -v           Verbose: run in foreground, log to stderr
  -vv          Very verbose: same as -v, plus per-packet hex dump
  -h           Show this help
```

### Examples

```bash
# Basic usage with explicit interface
fccproxy -p 8027 -s 10.0.0.1:8027 -i eth0 -vv

# Auto-detect local IP via routing
fccproxy -p 8027 -s 172.16.0.1:8027 -v
```

## How It Works

1. **Startup**: The proxy creates a UDP listening socket, determines its local IP, and enters the epoll event loop.
2. **Client detection**: When a packet arrives, the FMT field in the RTCP feedback header identifies the protocol (Huawei or Telecom) and message type (request, response, sync, termination).
3. **Session creation**: On the first valid request from a client, a session is created with dedicated server-side sockets.
4. **Protocol conversion**: `fcc_bridge()` translates packet fields (headers, addresses, ports, result codes, speed values) between the two formats.
5. **NAT rewriting**: Source/destination IPs and ports in the payload are rewritten so each side sees the proxy as the peer.
6. **Media forwarding**: RTP packets are forwarded without inspection between the paired signal/media sockets.
7. **Cleanup**: Idle sessions expire after 3 seconds; termination packets trigger a 1-second grace period before teardown.

## License

Copyright (C) 2026 ming

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
