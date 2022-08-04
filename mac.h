#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

int my_mac(char *argv, u_int8_t *mac);
