#include <stdlib.h>
#include <time.h>
#include "lwip/sys.h"

u32_t sys_jiffies(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (u32_t)((ts.tv_sec * 1000000000L) + ts.tv_nsec);
}
