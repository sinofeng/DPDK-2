#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_mtcp.a

CFLAGS += -O3
#CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_mtcp_version.map

LIBABIVER := 2

#
# all source are stored in SRCS-y
#
SRCS-y += addr_pool.c
SRCS-y += config.c
SRCS-y += debug.c
SRCS-y += eth_out.c
SRCS-y += icmp.c
SRCS-y += ip_out.c
SRCS-y += pipe.c
SRCS-y += tcp_in.c
SRCS-y += tcp_ring_buffer.c
SRCS-y += tcp_stream.c
SRCS-y += timer.c
SRCS-y += api.c
SRCS-y += core.c
SRCS-y += dpdk_module.c
SRCS-y += eventpoll.c
SRCS-y += io_module.c
SRCS-y += logger.c
SRCS-y += rss.c
SRCS-y += tcp_out.c
SRCS-y += tcp_sb_queue.c
SRCS-y += tcp_stream_queue.c
SRCS-y += arp.c
SRCS-y += cpu.c
SRCS-y += eth_in.c
SRCS-y += fhash.c
SRCS-y += ip_in.c
SRCS-y += memory_mgt.c
SRCS-y += socket.c
SRCS-y += tcp_send_buffer.c
SRCS-y += tcp_rb_frag_queue.c
SRCS-y += tcp_util.c


# install includes
SYMLINK-y-include += addr_pool.h cpu.h eth_out.h ip_in.h ps.h
SYMLINK-y-include += memory_mgt.h mtcp.h rss.h tcp_in.h tcp_ring_buffer.h tcp_stream.h timer.h
SYMLINK-y-include += arp.h debug.h eventpoll.h icmp.h ip_out.h mtcp_api.h
SYMLINK-y-include += socket.h tcp_out.h tcp_sb_queue.h tcp_stream_queue.h
SYMLINK-y-include += config.h eth_in.h fhash.h io_module.h logger.h
SYMLINK-y-include += mtcp_epoll.h pipe.h stat.h tcp_rb_frag_queue.h tcp_send_buffer.h tcp_util.h

# install includes
#SYMLINK-y-include += rte_mtcp.h

include $(RTE_SDK)/mk/rte.lib.mk
