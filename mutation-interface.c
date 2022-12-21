#include "mutation-interface.h"
#include "mutation.h"
#include "string.h"

//gcc -c -Wall -Werror -fPIC mutation-interface.c
//gcc -shared -o libmutation-interface.so mutation-interface.o 



static void print_hex(unsigned char * bin_data, size_t len)

{
    size_t i;

    for( i = 0; i < len; ++i )
    {
        printf( "%.2X ", bin_data[ i ] );
    }

    printf( "\n" );
}

struct packet *mutate(struct packet *original, struct fuzz_options *fuzz_options) {
    printf("Mutating packet 3...\n");

    if (fuzz_options == NULL || fuzz_options->size == 0) {
        printf("fuzz options is empty\n");
        return original;
    }

    printf("Original network packet\n");
    print_hex((unsigned char *)original->buffer, original->buffer_bytes);

    for (int i = 0; i < fuzz_options->count; i++) {
        
        struct fuzz_option option;
        memcpy(&option, (fuzz_options->options)++, sizeof(struct fuzz_option));

        printf("option value: and option len: %d...\n", option.fuzz_value_byte_count);

        int ipv4Offset = original->ipv4 - original->buffer;
        int tcpOffset = original->tcp - original->buffer;
        printf("ipv4 offset: %d... tcp offset: %d...\n", ipv4Offset, tcpOffset);

        u8 tcpLengthField = original->tcp[12] >> 4;
        printf("The tcp header length is %d...\n", tcpLengthField);

        u8 ipLengthField = original->ipv4[0] & 0x0F;
        printf("The ip header length is %d...\n", ipLengthField);

        u8 ipTotalLengthField = original->ipv4[3];
        printf("The total length of the packet is %d...\n", ipTotalLengthField);

        printf("Printing certain 4 bytes of TCP header...\n");
        print_hex(original->tcp + 12, 4);

        u8 newTotalLengthField;

        switch (option.fuzz_type){
        case OP_REPLACE:
            printf("Mutating network packet: replace\n");
            if (option.fuzz_field == F_SOURCE_PORT) {
                memcpy(original->tcp, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_DST_PORT) {
                memcpy(original->tcp + 2, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_SEQ_NUM) {
                memcpy(original->tcp + 4, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_ACK_NUM) {
                memcpy(original->tcp + 8, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_TCP_HDR_LEN) {
                memcpy(original->tcp + 12, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_FLAGS) {
                memcpy(original->tcp + 13, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_WIN_SIZE) {
                memcpy(original->tcp + 14, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_TCP_CHECKSUM) {
                memcpy(original->tcp + 16, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_URG_POINTER) {
                memcpy(original->tcp + 18, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_VERSION_IHL) {
                memcpy(original->ipv4, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_DSCP_ESN) {
                memcpy(original->ipv4 + 1, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_TOT_LEN) {
                memcpy(original->ipv4 + 2, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_IDEN) {
                memcpy(original->ipv4 + 4, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_FLAGS_FLAGOFF) {
                memcpy(original->ipv4 + 6, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_TTL) {
                memcpy(original->ipv4 + 8, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_PROTOCOL) {
                memcpy(original->ipv4 + 9, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_IP_CHECKSUM) {
                memcpy(original->ipv4 + 10, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_SRC_IP) {
                memcpy(original->ipv4 + 12, option.fuzz_value, option.fuzz_value_byte_count);
            } else if (option.fuzz_field == F_DEST_IP) {
                memcpy(original->ipv4 + 16, option.fuzz_value, option.fuzz_value_byte_count);
            }
            break;
        case OP_INSERT:
        // For now, don't add insert instruction without data fields
            printf("Mutating network packet: insert...\n");
            
            original->buffer = realloc(original->buffer, original->buffer_bytes + option.fuzz_value_byte_count);

            // For TCP (2), insert location is x bytes after the ip header
            // We assume the packet originally has no IP options
            int insertLocation = option.header_type == 2 ? 20 + option.fuzz_field : option.fuzz_field;
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
            original->ipv4 = original->buffer + ipv4Offset;
            original->tcp = original->buffer +tcpOffset;

            // Now we update the length fields of the various headers
            if (option.header_type == 2) {
                // Update the tcp header length field
                u8 newTcpLengthField = (tcpLengthField + ((option.fuzz_value_byte_count + 3) / 4)) << 4; // https://stackoverflow.com/a/2422722
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
            newTotalLengthField = ipTotalLengthField + option.fuzz_value_byte_count;
            original->ipv4[3] = newTotalLengthField;
            
            break;

        case OP_TRUNCATE:
            printf("Mutating network packet: truncate\n");

            int numBytesToTrun = atoi(option.fuzz_value);

            int truncateStartIndex = option.header_type == 2 ? 20 + option.fuzz_field : option.fuzz_field;
            int truncateEndIndex = truncateStartIndex + numBytesToTrun;
            bool bytesAfterTruncation = original->buffer_bytes - truncateEndIndex; // There are data after the region being truncated

            if (bytesAfterTruncation > 0) {
                // remove bytes between truncateStartIndex and truncateEndIndex from original->buffer
                memmove(original->buffer + truncateStartIndex, original->buffer + truncateEndIndex, bytesAfterTruncation);
            }

            original->buffer_bytes = original->buffer_bytes - numBytesToTrun;
            original->ipv4 = original->buffer + ipv4Offset;
            original->tcp = option.header_type < 2 ? original->buffer + tcpOffset - numBytesToTrun : original->buffer + tcpOffset;

            int tcpBytes = (original->buffer + original->buffer_bytes) - (original->tcp);

            // Now we update the length fields of the various headers
            if (option.header_type == 2 && tcpBytes >= 12) { // TCP header was truncated but length field still exists
                // Update the tcp header length field
                u8 newTcpLengthField = (tcpLengthField - ((numBytesToTrun + 3) / 4)) << 4; // https://stackoverflow.com/a/2422722
                // We keep the last 4 bits and replace the first 4 bits
                original->tcp[12] = (original->tcp[12] & 0b00001111) | newTcpLengthField; 
            } else if (option.header_type == 1) {
                // No implementation yet for IPv6
            } else if (option.header_type == 0) {
                u8 newIPv4LengthField = (ipLengthField - ((numBytesToTrun + 3) / 4));
                // We keep the first 4 bits and replace the second 4 bits
                original->ipv4[0] = (original->ipv4[0] & 0b11110000) | newIPv4LengthField;
            }

            // Update the ip total length field
            // While the total length field is 2 bytes, for most cases, only the second byte is expected to change. Hence, we will change only the second byte
            newTotalLengthField = ipTotalLengthField - numBytesToTrun;
            printf("New total length field: %d\n", newTotalLengthField);
            original->ipv4[3] = newTotalLengthField;
            printf("original->ipv4[3]: %d\n", original->ipv4[3]);

            break;
            
        }
    }

    printf("Mutated network packet\n");
    print_hex((unsigned char *)original->buffer, original->buffer_bytes);
    

    
    return original;
}
	
    
void free_interface() {

    printf("Freeing mutation interface...\n");

}


void fm_interface_init(struct fm_interface *interface) {

    printf("Initializing mutation interface...\n");
    interface->free = free_interface;
    interface->mutate = mutate;
}
