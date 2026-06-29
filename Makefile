# Copyright (C) 2026 ming
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Makefile for fccproxy — FCC Protocol Proxy (Huawei ↔ Telecom)
#
# Targets:
#   make                         Build with the host compiler
#   make CROSS_COMPILE=aarch64-linux-gnu-
#                                Cross-build with a traditional toolchain prefix
#   make CC=aarch64-linux-gnu-gcc
#                                Cross-build with an explicit compiler
#   make install DESTDIR=/tmp/pkg PREFIX=/usr
#                                Install to $(DESTDIR)$(PREFIX)/sbin
#   make clean                   Remove build artifacts

CROSS_COMPILE ?=
ifeq ($(origin CC),default)
CC := $(CROSS_COMPILE)gcc
endif
INSTALL ?= install

CPPFLAGS ?= -D_GNU_SOURCE
CFLAGS   ?= -Wall -Wextra -O2
LDFLAGS  ?=
LDLIBS   ?=

PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin

# Path
SRC_DIR   ?= src
BUILD_DIR ?= build

TARGET   ?= fccproxy
SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

.PHONY: all clean install arm64

all: $(TARGET)

arm64: CC := aarch64-linux-gnu-gcc
arm64: all

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

install: $(TARGET)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 $(TARGET) $(DESTDIR)$(SBINDIR)/$(TARGET)

clean:
	rm -rf $(TARGET) $(BUILD_DIR)
