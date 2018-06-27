#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <errno.h>

#include "../portchange.h"

#define MAXBUFSIZE 65536

int main (int argc, char **argv)
{
    int sock, status, socklen, i;
    char buffer[MAXBUFSIZE+1];
    struct sockaddr_in saddr;

    int fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) {
        printf("open %s failed: errno = %d\n", DEVICE_NAME, errno);
        return -1;
    }

    unsigned short port_array[5];
    for (i = 0; i < 5; i++) {
        port_array[i] = 10000 + i;
    }

    struct pc_req_register_s reg;
    reg.port = 20001;
    reg.key = PC_REQUEST_KEY;
    reg.array_num = 5;
    reg.port_array = port_array;

    if (ioctl(fd, PC_REQUEST_REGISTER, &reg) < 0) {
        printf("ioctl error: %d\n", errno); 
        return -1;
    }

    reg.port = 20000;
    if (ioctl(fd, PC_REQUEST_REGISTER, &reg) < 0) {
        printf("ioctl error: %d\n", errno);
        return -1;
    }

    if (ioctl(fd, PC_REQUEST_UNREGISTER, 20001) < 0) {
        printf("ioctl unregister error: %d\n", errno);
        return -1;
    } 
 
    memset(&saddr, 0, sizeof(struct sockaddr_in));

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed!");
        return 1;
    }

    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(10001);
    saddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    status = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (status < 0) {
        perror("bind failed!");
        return 1;
    }

    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(29999);
    saddr.sin_addr.s_addr = inet_addr("192.168.100.100");
    status = connect(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (status < 0) {
        perror("connect failed!");
        return 1;
    }

    while (1) {
        status = read(sock, buffer, sizeof(buffer));
        if (status <= 0) {
            perror("read error");
            return 1;
        }

        buffer[status] = 0;
        printf("buffer = %s\n", buffer);

        buffer[0] = 'p';

        status = write(sock, buffer, status);
        printf("status = %d\n", status);
    }
}
