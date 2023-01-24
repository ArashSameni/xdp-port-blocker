#include <stdio.h>
#include <stdbool.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include "./common/common_defines.h"
#include "./common/common_user_bpf_xdp.h"

const char *pin_basedir =  "/sys/fs/bpf";

int main()
{
	char ifname[STR_MAX];
	printf("Interface name: ");
	scanf("%s", ifname);

	char pin_dir[STR_MAX];
	int len = snprintf(pin_dir, STR_MAX, "%s/%s", pin_basedir, ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	int map_fd = open_bpf_map_file(pin_dir, "blocked_ports", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	__u16 port;
	printf("Port: ");
	scanf("%hu", &port);

	char c;
	printf("Block(y/n): ");
	while ((c = getchar()) != '\n' && c != EOF);
	scanf("%c", &c);

	bool to_block = true;
	switch (c) {
		case 'y':
			if (bpf_map_update_elem(map_fd, &port, &to_block, 0) < 0) {
				fprintf(stderr, "ERR: couldn't update map\n");
				return EXIT_FAIL_BPF;
			}
			printf("Port %hu on tcp/udp is now blocked\n", port);
			break;
		
		case 'n':
			if (bpf_map_delete_elem(map_fd, &port) < 0) {
				fprintf(stderr, "ERR: couldn't update map\n");
				return EXIT_FAIL_BPF;
			}
			printf("Port %hu on tcp/udp is now unblocked\n", port);
			break;
		
		default:
	}

	return EXIT_OK;
}