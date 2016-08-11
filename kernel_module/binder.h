#ifndef MYBINDER_BINDER_H_
#define MYBINDER_BINDER_H_

#include <linux/types.h>
#include <linux/ioctl.h>

#define BINDER_IPC_32BIT

#ifdef BINDER_IPC_32BIT
typedef __u32 binder_uintptr_t;
#else
typedef __u64 binder_uintptr_t;
#endif

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, __s32)

#endif  // MYBINDER_BINDER_H_
