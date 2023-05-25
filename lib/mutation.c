#include "mutation.h"

/**
 * Generate a random number (from 0 to limit - 1). This may
 * have slight bias.
*/
static inline u32 UR(u32 limit) {
    return random() % limit;
}

