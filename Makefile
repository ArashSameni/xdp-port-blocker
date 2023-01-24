# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS := user xdp_loader
XDP_TARGETS  := kern

LIBBPF_DIR = ./libbpf/src/
COMMON_DIR = ./common

include $(COMMON_DIR)/common.mk
