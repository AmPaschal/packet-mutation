#include "types.h"

struct fuzz_options {
    struct fuzz_option *options;  // Pointer to first fuzz_option
    u8 capacity;    // Allocated space in the buffer 
    u8 size;        // Size (in bytes) of items in the buffer
    u8 count;       // Count of fuzz instructions in the buffer
};

enum field_name_t {
    F_SOURCE_PORT = 0,
    F_DST_PORT = 1,
    F_SEQ_NUM = 2,
    F_ACK_NUM = 3,
    F_TCP_HDR_LEN = 4,
    F_FLAGS = 5,
    F_WIN_SIZE = 6,
    F_TCP_CHECKSUM = 7,
    F_URG_POINTER = 8,
    F_VERSION_IHL = 9,
    F_DSCP_ESN = 10,
    F_TOT_LEN = 11,
    F_IDEN = 12,
    F_FLAGS_FLAGOFF = 13,
    F_TTL = 14,
    F_PROTOCOL = 15,
    F_IP_CHECKSUM = 16,
    F_SRC_IP = 17,
    F_DEST_IP = 18
};

enum fuzz_type_t {
    OP_REPLACE = 0,
    OP_TRUNCATE = 1,
    OP_INSERT = 2
};

enum header_type_t {
    IPv4 = 0,
    IPv6 = 1,
    xTCP = 2,
    xUDP = 3
};

struct fuzz_option {
    enum fuzz_type_t fuzz_type;
    enum header_type_t header_type;
    u8 fuzz_field;
    char *fuzz_value;
    u8 fuzz_value_byte_count;
} __packed;

struct fuzz_value_t {
    char *value;
    u8 byte_count;
};

/* TCP/UDP/IPv4 packet, including IPv4 header, TCP/UDP header, and data. There
 * may also be a link layer header between the 'buffer' and 'ip'
 * pointers, but we typically ignore that. The 'buffer_bytes' field
 * gives the total space in the buffer, which may be bigger than the
 * actual amount occupied by the packet data.
 */
struct packet {
	u8 *buffer;		/* data buffer: full contents of packet */
    u32 buffer_bytes;   /* bytes of space in data buffer */

	/* Layer 3 */
	u8 *ipv4;	/* start of IPv4 header, if present */
	u8 *ipv6;	/* start of IPv6 header, if present */

	/* Layer 4 */
	u8 *tcp;	/* start of TCP header, if present */
	u8 *udp;	/* start of UDP header, if present */
	u8 *icmpv4;	/* start of ICMPv4 header, if present */
	u8 *icmpv6;	/* start of ICMPv6 header, if present */
};

struct fm_interface {
	struct packet* (*mutate)(struct packet *original, struct fuzz_options *fuzz_options);
	void (*free)();
};

void fm_interface_init(struct fm_interface *interface);