/**
 * Mutation interface
 */

/* Includes */
#include "mutation-interface.h"
#include "mutation.h"
#include "string.h"
#include "log.h"

/**
 * Print a byte sequence in hex representation
 * @param bin_data buffer to represent
 * @param len buffer length
 */
void print_hex(unsigned char *bin_data, unsigned long len) {
    char* buf = malloc(3 * len + 1);
    char* temp = malloc(3);
    if(buf != NULL && temp != NULL){
        *buf = '\0';
        for(unsigned long i = 0; i < len; i++){
            sprintf(temp, "%.2X ", bin_data[i]);
            strcat(buf, temp);
        }
    }
    log_info(buf);
    free(buf);
    free(temp);
}

/**
 * Mutate a packet depending on options
 * @param original Packet to mutate
 * @param fuzz_options Options for mutation
 * @return Mutated packet
 */
struct packet *mutate(struct packet *original, struct fuzz_options *fuzz_options) {
    log_set_level(LOG_INFO);
    log_info("Mutating packet.");
    if (fuzz_options == NULL || fuzz_options->size == 0) {
        log_warn("fuzz options is empty.");
        return original;
    }
    log_info("Original network packet:");
    print_hex((unsigned char *) original->buffer, original->buffer_bytes);

    u8 isIPv4 = original->ipv4 != NULL;
    u8 isIPv6 = original->ipv6 != NULL;
    u8 isTCP = original->tcp != NULL;
    u8 isUDP = original->udp != NULL;

    for (int i = 0; i < fuzz_options->count; i++) {
        struct fuzz_option option;
        memcpy(&option, (fuzz_options->options)++, sizeof(struct fuzz_option));

        log_debug("Option value: and Option len: %d...\n", option.fuzz_value_byte_count);

        int ipOffset = 0;
        if (isIPv4){
            ipOffset = original->ipv4 - original->buffer;
        }else if (isIPv6){
            ipOffset = original->ipv6 - original->buffer;
        }

        u8 transOffset = 0; // Offset of the transport protocol header from start of packet
        u8 tcpHeaderLength = 0; // Length of the tcp header
        u16 udpLength = 0; // Length of the UDP header + data

        if (isTCP) {
            transOffset = original->tcp - original->buffer;
            log_debug("ip offset: %d... tcp offset: %d...\n", ipOffset, transOffset);
            tcpHeaderLength = original->tcp[12] >> 4;
            log_debug("The tcp header length is %d...\n", tcpHeaderLength);
        } else if (isUDP) {
            transOffset = original->udp - original->buffer;
            log_debug("ip offset: %d... udp offset: %d...\n", ipOffset, transOffset);
            udpLength = *(original->udp + 4) << 8 | *(original->udp+ 5);
            log_debug("The udp length is %d...\n", udpLength);
        }

        u8 ipLengthField = isIPv4 ? original->ipv4[0] & 0x0F : 10;
        log_debug("The ip header length is %d.", ipLengthField);

        u8 ipTotalLengthField = isIPv4 ? original->ipv4[3] : 0;
        log_debug("The total length of the packet is %d.", ipTotalLengthField);

        u8 nextHeaderLength = isIPv4 ? 0 : original->ipv6[5];

        u8 newTotalLengthField;

        switch (option.fuzz_type) {
            case OP_REPLACE: {
                log_debug("Mutating network packet: replace.");
                if (isTCP && option.header_type == xTCP) {
                    if (option.fuzz_field == F_SRC_PORT) {
                        for(int i = 0; i < 2; i++){
                            *(original->tcp + i) = *(option.fuzz_value + i);
                        }
                    } else if (option.fuzz_field == F_DST_PORT) {
                        for(int i = 2; i < 4; i++){
                            *(original->tcp + i) = *(option.fuzz_value - 2 + i);
                        }
                    } else if (option.fuzz_field == F_SEQ_NUM) {
                        for(int i = 4; i < 8; i++){
                            *(original->tcp + i) = *(option.fuzz_value - 4 + i);
                        }
                    } else if (option.fuzz_field == F_ACK_NUM) {
                        for(int i = 8; i < 12; i++){
                            *(original->tcp + i) = *(option.fuzz_value - 8 + i);
                        }
                    } else if (option.fuzz_field == F_DATA_OFF) {
                        char value = (*option.fuzz_value << 4) & 0xF0;
                        char complement = *(original->tcp + 12) & 0x0F;
                        *(original->tcp + 12) = complement | value;
                    } else if (option.fuzz_field == F_RESERVED) {
                        char value = *option.fuzz_value & 0x0F;
                        char complement = *(original->tcp + 12) & 0xF0;
                        *(original->tcp + 12) = complement | value;
                    } else if (option.fuzz_field == F_FLAGS) {
                        *(original->tcp + 13) = *option.fuzz_value;
                    } else if (option.fuzz_field == F_CWR_FLAG) {
                        *(original->tcp + 13) = *option.fuzz_value;
                        char value = (*option.fuzz_value << 7) & 0x80;
                        char complement = *(original->tcp + 13) & 0x7F;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_ECE_FLAG) {
                        *(original->tcp + 13) = *option.fuzz_value;
                        char value = (*option.fuzz_value << 6) & 0x40;
                        char complement = *(original->tcp + 13) & 0xBF;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_URG_FLAG) {
                        *(original->tcp + 13) = *option.fuzz_value;
                        char value = (*option.fuzz_value << 5) & 0x20;
                        char complement = *(original->tcp + 13) & 0xDF;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_ACK_FLAG) {
                        *(original->tcp + 13) = *option.fuzz_value;
                        char value = (*option.fuzz_value << 4) & 0x10;
                        char complement = *(original->tcp + 13) & 0xEF;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_PSH_FLAG) {
                        *(original->tcp + 13) = *option.fuzz_value;
                        char value = (*option.fuzz_value << 3) & 0x08;
                        char complement = *(original->tcp + 13) & 0xF7;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_RST_FLAG) {
                        *(original->tcp + 13) = *option.fuzz_value;
                        char value = (*option.fuzz_value << 2) & 0x04;
                        char complement = *(original->tcp + 13) & 0xFB;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_SYN_FLAG) {
                        char value = (*option.fuzz_value << 1) & 0x02;
                        char complement = *(original->tcp + 13) & 0xFD;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_FIN_FLAG) {
                        char value = *option.fuzz_value & 0x01;
                        char complement = *(original->tcp + 13) & 0xFE;
                        *(original->tcp + 13) = complement | value;
                    } else if (option.fuzz_field == F_WIN_SIZE) {
                        for(int i = 14; i < 16; i++){
                            *(original->tcp + i) = *(option.fuzz_value - 14 + i);
                        }
                    } else if (option.fuzz_field == F_CHECKSUM) {
                        for(int i = 16; i < 18; i++){
                            *(original->tcp + i) = *(option.fuzz_value - 16 + i);
                        }
                    } else if (option.fuzz_field == F_URG_POINTER) {
                        for(int i = 18; i < 20; i++){
                            *(original->tcp + i) = *(option.fuzz_value - 18 + i);
                        }
                    }
                }

                if (isUDP && option.header_type == xUDP) {
                    if(option.fuzz_field == F_SRC_PORT){
                        for(int i = 0; i < 2; i++){
                            *(original->udp + i) = *(option.fuzz_value + i);
                        }
                    } else if(option.fuzz_field == F_DST_PORT) {
                        for(int i = 2; i < 4; i++){
                            *(original->udp + i) = *(option.fuzz_value - 2 + i);
                        }
                    } else if(option.fuzz_field == F_UDP_LEN) {
                        for(int i = 4; i < 6; i++){
                            *(original->udp + i) = *(option.fuzz_value - 4 + i);
                        }
                    } else if(option.fuzz_field == F_CHECKSUM) {
                        for(int i = 6; i < 8; i++){
                            *(original->udp + i) = *(option.fuzz_value - 6 + i);
                        }
                    }
                }

                if (isIPv4 && option.header_type == IPv4) {
                    if (option.fuzz_field == F_VERSION) {
                        char value = (*option.fuzz_value << 4) & 0xF0;
                        char complement = *original->ipv4 & 0x0F;
                        *original->ipv4 = complement | value;
                    } else if (option.fuzz_field == F_IHL) {
                        char value = *option.fuzz_value & 0x0F;
                        char complement = *original->ipv4 & 0xF0;
                        *original->ipv4 = complement | value;
                    } else if (option.fuzz_field == F_DSCP) {
                        char value = (*option.fuzz_value << 2) & 0xFC;
                        char complement = *(original->ipv4 + 1) & 0x03;
                        *(original->ipv4 + 1) = complement | value;
                    } else if (option.fuzz_field == F_ECN) {
                        char value = *option.fuzz_value & 0x03;
                        char complement = *(original->ipv4 + 1) & 0xFC;
                        *(original->ipv4 + 1) = complement | value;
                    } else if (option.fuzz_field == F_TOT_LEN) {
                        for(int i = 2; i < 4; i++){
                            *(original->ipv4 + i) = *(option.fuzz_value - 2 + i);
                        }
                    } else if (option.fuzz_field == F_IDEN) {
                        for(int i = 4; i < 6; i++){
                            *(original->ipv4 + i) = *(option.fuzz_value - 4 + i);
                        }
                    } else if (option.fuzz_field == F_FLAGS) {
                        char value = (*option.fuzz_value << 5) & 0xE0;
                        char complement = *(original->ipv4 + 6) & 0x1F;
                        *(original->ipv4 + 6) = complement | value;
                    } else if (option.fuzz_field == F_RSV_FLAG) {
                        char value = (*option.fuzz_value << 7) & 0x80;
                        char complement = *(original->ipv4 + 6) & 0x7F;
                        *(original->ipv4 + 6) = complement | value;
                    } else if (option.fuzz_field == F_DF_FLAG) {
                        char value = (*option.fuzz_value << 6) & 0x40;
                        char complement = *(original->ipv4 + 6) & 0xBF;
                        *(original->ipv4 + 6) = complement | value;
                    } else if (option.fuzz_field == F_MF_FLAG) {
                        char value = (*option.fuzz_value << 5) & 0x20;
                        char complement = *(original->ipv4 + 6) & 0xDF;
                        *(original->ipv4 + 6) = complement | value;
                    } else if (option.fuzz_field == F_FRAG_OFF) {
                        char value = *option.fuzz_value & 0x1F;
                        char complement = *(original->ipv4 + 6) & 0xE0;
                        *(original->ipv4 + 6) = complement | value;
                        *(original->ipv4 + 7) = *(option.fuzz_value + 1);
                    } else if (option.fuzz_field == F_TTL) {
                        *(original->ipv4 + 8) = *option.fuzz_value;
                    } else if (option.fuzz_field == F_PROTOCOL) {
                        *(original->ipv4 + 9) = *option.fuzz_value;
                    } else if (option.fuzz_field == F_CHECKSUM) {
                        for(int i = 10; i < 12; i++){
                            *(original->ipv4 + i) = *(option.fuzz_value - 10 + i);
                        }
                    } else if (option.fuzz_field == F_SRC_ADDR) {
                        for(int i = 12; i < 16; i++){
                            *(original->ipv4 + i) = *(option.fuzz_value - 12 + i);
                        }
                    } else if (option.fuzz_field == F_DST_ADDR) {
                        for(int i = 16; i < 20; i++){
                            *(original->ipv4 + i) = *(option.fuzz_value - 16 + i);
                        }
                    }
                }
                if (isIPv6 && option.header_type == IPv6) {
                    if (option.fuzz_field == F_VERSION) {
                        char value = (*option.fuzz_value << 4) & 0xF0;
                        char complement = *original->ipv6 & 0x0F;
                        *original->ipv6 = complement | value;
                    } else if (option.fuzz_field == F_TRF_CLASS) {
                        char value = (*option.fuzz_value >> 4) & 0x0F;
                        char complement = *original->ipv6 & 0xF0;
                        *original->ipv6 = complement | value;

                        value = (*option.fuzz_value << 4) & 0xF0;
                        complement = *(original->ipv6 + 1) & 0x0F;
                        *(original->ipv6 + 1) = complement | value;
                    } else if (option.fuzz_field == F_FLOW_LABEL) {
                        char value = *option.fuzz_value & 0x0F;
                        char complement = *(original->ipv6 + 1) & 0xF0;
                        *(original->ipv6 + 1) = complement | value;
                        *(original->ipv6 + 2) = *(option.fuzz_value + 1);
                        *(original->ipv6 + 3) = *(option.fuzz_value + 2);
                    } else if (option.fuzz_field == F_PYLD_LEN) {
                        for(int i = 4; i < 6; i++){
                            *(original->ipv6 + i) = *(option.fuzz_value - 4 + i);
                        }
                    } else if (option.fuzz_field == F_NEXT_HEADER) {
                        *(original->ipv6 + 6) = *option.fuzz_value;
                    } else if (option.fuzz_field == F_HOP_LIMIT) {
                        *(original->ipv6 + 7) = *option.fuzz_value;
                    } else if (option.fuzz_field == F_SRC_ADDR) {
                        for(int i = 8; i < 24; i++){
                            *(original->ipv6 + i) = *(option.fuzz_value - 8 + i);
                        }
                    } else if (option.fuzz_field == F_DST_ADDR) {
                        for(int i = 24; i < 40; i++){
                            *(original->ipv6 + i) = *(option.fuzz_value - 24 + i);
                        }
                    }
                }
                break;
            }
            case OP_INSERT: 
            // For now, don't add insert instruction without data fields
            log_debug("Mutating network packet: insert...\n");
            
            original->buffer = realloc(original->buffer, original->buffer_bytes + option.fuzz_value_byte_count);

            // For TCP (2), insert location is x bytes after the ip header
            // We assume the packet originally has no IP options
            int insertLocation = option.header_type >= 2 ? (ipLengthField << 2) + option.fuzz_field : option.fuzz_field; // If inserting to TCP or UDP, add insert location to after IP header
            u8 numBytesToMove = original->buffer_bytes - insertLocation;
            if (numBytesToMove > 0) {
                u8 *dest = original->buffer + insertLocation + option.fuzz_value_byte_count;
                u8 *src = original->buffer + insertLocation;
                memmove(dest, src, numBytesToMove);
            }
            memcpy(original->buffer + insertLocation, option.fuzz_value, option.fuzz_value_byte_count);
            original->buffer_bytes = original->buffer_bytes + option.fuzz_value_byte_count;

            // Confirm TCP header length is a multiple of 4 bytes
            // Update header length field in TCP and IP headers

            // TODO: Verify if offset got updated when ip options are added
            if (isIPv4) {
                original->ipv4 = original->buffer + ipOffset;
            } else {
                original->ipv6 = original->buffer + ipOffset;
            }
            
            if (isTCP) {
                original->tcp = option.header_type < 2 ? original->buffer + transOffset + option.fuzz_value_byte_count : original->buffer + transOffset;
            } else if (isUDP) {
                original->udp = option.header_type < 2 ? original->buffer + transOffset + option.fuzz_value_byte_count : original->buffer + transOffset;
            }
            

            // Now we update the length fields of the various headers
            if (option.header_type == 3) {
                // Update the tcp header length field
                u16 newUdpField = udpLength + option.fuzz_value_byte_count;
                // We keep the last 4 bits and replace the first 4 bits
                *(original->udp + 4) = newUdpField >> 8;
                *(original->udp + 5) = newUdpField & 0xff;
            } else if (option.header_type == 2) {
                // Update the tcp header length field
                u8 newTcpLengthField = (tcpHeaderLength + ((option.fuzz_value_byte_count + 3) / 4)) << 4; // https://stackoverflow.com/a/2422722
                // We keep the last 4 bits and replace the first 4 bits
                original->tcp[12] = (original->tcp[12] & 0b00001111) | newTcpLengthField; 
            } else if (option.header_type == 1) {
                // No implementation yet for IPv6
            } else if (option.header_type == 0) {
                u8 newIPv4LengthField = (ipLengthField + ((option.fuzz_value_byte_count + 3) / 4));
                // We keep the first 4 bits and replace the second 4 bits
                original->ipv4[0] = (original->ipv4[0] & 0b11110000) | newIPv4LengthField;
            }

            // Update the ip total length field
            // While the total length field is 2 bytes, for most cases, only the second byte is expected to change. Hence, we will change only the second byte
            if (isIPv4) {
                newTotalLengthField = ipTotalLengthField + option.fuzz_value_byte_count;
                original->ipv4[3] = newTotalLengthField;
            } else {
                if (option.header_type >= 2) { // Transport protocol length was updated
                    original->ipv6[5] = nextHeaderLength + option.fuzz_value_byte_count;
                }
            }
            
            
            break;

        case OP_TRUNCATE:
            printf("Mutating network packet: truncate\n");

            int numBytesToTrun = atoi(option.fuzz_value);

            int truncateStartIndex = option.header_type == 2 ? (ipLengthField << 2) + option.fuzz_field : option.fuzz_field;
            int truncateEndIndex = truncateStartIndex + numBytesToTrun;
            bool bytesAfterTruncation = original->buffer_bytes - truncateEndIndex; // There are data after the region being truncated

            if (bytesAfterTruncation > 0) {
                // remove bytes between truncateStartIndex and truncateEndIndex from original->buffer
                memmove(original->buffer + truncateStartIndex, original->buffer + truncateEndIndex, bytesAfterTruncation);
            }

            original->buffer_bytes = original->buffer_bytes - numBytesToTrun;
            if (isIPv4) {
                original->ipv4 = original->buffer + ipOffset;
            } else {
                original->ipv6 = original->buffer + ipOffset;
            }

            if (isTCP) {
                original->tcp = option.header_type < 2 ? original->buffer + transOffset - numBytesToTrun : original->buffer + transOffset;
            } else if (isUDP) {
                original->udp = option.header_type < 2 ? original->buffer + transOffset - numBytesToTrun : original->buffer + transOffset;
            }
            
            

            // Now we update the length fields of the various headers
            if (option.header_type == 3) {
                int udpBytes = (original->buffer + original->buffer_bytes) - (original->udp);

                if (udpBytes >= 5) {
                    // Update the udp length field
                    u16 newUdpLengthField = udpLength - numBytesToTrun;
                    // We set the 16 bit udp length field
                    *(original->udp + 4) = newUdpLengthField >> 8;
                    *(original->udp + 5) = newUdpLengthField & 0xff;
                }
            } else if (option.header_type == 2 ) { // TCP header was truncated but length field still exists
                int tcpBytes = (original->buffer + original->buffer_bytes) - (original->tcp);

                if (tcpBytes >= 12) {
                    // Update the tcp header length field
                    u8 newTcpLengthField = (tcpHeaderLength - ((numBytesToTrun + 3) / 4)) << 4; // https://stackoverflow.com/a/2422722
                    // We keep the last 4 bits and replace the first 4 bits
                    original->tcp[12] = (original->tcp[12] & 0b00001111) | newTcpLengthField; 
                }
            } else if (option.header_type == 1) {
                // No implementation yet for IPv6
            } else if (option.header_type == 0) {
                u8 newIPv4LengthField = (ipLengthField - ((numBytesToTrun + 3) / 4));
                // We keep the first 4 bits and replace the second 4 bits
                original->ipv4[0] = (original->ipv4[0] & 0b11110000) | newIPv4LengthField;
            }

            // Update the ip total length field
            // While the total length field is 2 bytes, for most cases, only the second byte is expected to change. Hence, we will change only the second byte
            if (isIPv4) {
                newTotalLengthField = ipTotalLengthField - numBytesToTrun;
                printf("New total length field: %d\n", newTotalLengthField);
                original->ipv4[3] = newTotalLengthField;
                printf("original->ipv4[3]: %d\n", original->ipv4[3]);
            } else {
                if (option.header_type >= 2) { // Transport protocol length was updated
                    original->ipv6[5] = nextHeaderLength - numBytesToTrun;
                }
            }
            

            break;
            
        }
    }

    log_info("Mutated network packet: ");
    print_hex((unsigned char *)original->buffer, original->buffer_bytes);
    return original;
}
	
/**
 * Free Interface function
 */
void free_interface() {
    log_info("Freeing mutation interface.");
}

/**
 * Setting function callbacks for mutation
 * @param interface interface to execute
 */
void fm_interface_init(struct fm_interface *interface) {
    log_info("Initializing mutation interface.");
    interface->free = free_interface;
    interface->mutate = mutate;
}
