#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "./common/parsing_helpers.h"

struct bpf_map_def SEC("maps") blocked_ports = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),
	.value_size = 1,
	.max_entries = sizeof(__u16),
	.map_flags = BPF_F_NO_PREALLOC,
};

SEC("xdp_packet_parser")
int xdp_parser_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = {.pos = data};

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	int dest_port;
	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		dest_port = bpf_ntohs(udphdr->dest);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		dest_port = bpf_ntohs(tcphdr->dest);
	} else {
		goto out;
	}

	bool *should_drop = bpf_map_lookup_elem(&blocked_ports, &dest_port);
	if (should_drop != 0 && *should_drop) {
		action = XDP_DROP;
	}

out:
	return action;
}

char _license[] SEC("license") = "GPL";
