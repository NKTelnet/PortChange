#ifndef __PORTCHANGE_H__
#define __PORTCHANGE_H__    1

#include <asm-generic/ioctl.h>

#define DEVICE_NAME "/dev/crystal"
#define PC_REQUEST_KEY 1387

#define PC_REQUEST_REGISTER 0x4
#define PC_REQUEST_UNREGISTER 0x5 

struct pc_req_register_s {
    uint16_t port;
    uint16_t key;
    uint32_t array_num;
    uint16_t *port_array;
};

#endif // #ifndef __PORTCHANGE_H__
