#include <stdlib.h>

#include "../../tracy.h"

int get_abi(struct tracy_event *s) {
    (void) s;

    return 0;
}

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi) {
    (void) abi;

    switch (reg) {
        case 0:
            return r->regs[0];
            break;
        case 1:
            return r->regs[1];
            break;
        case 2:
            return r->regs[2];
            break;
        case 3:
            return r->regs[3];
            break;
        case 4:
            return r->regs[4];
            break;
        case 5:
            return r->regs[5];
            break;
    }

    /* We should never reach this */
    return -1;
}

long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val) {
    (void) abi;

    switch (reg) {
        case 0:
            r->regs[0] = val;
            break;
        case 1:
            r->regs[1] = val;
            break;
        case 2:
            r->regs[2] = val;
            break;
        case 3:
            r->regs[3] = val;
            break;
        case 4:
            r->regs[4] = val;
            break;
        case 5:
            r->regs[5] = val;
            break;
    }

    return 0;
}
