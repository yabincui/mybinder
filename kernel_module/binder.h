#ifndef MYBINDER_BINDER_H_
#define MYBINDER_BINDER_H_

#include <linux/types.h>
#include <linux/ioctl.h>

#define BINDER_IPC_32BIT

#ifdef BINDER_IPC_32BIT
typedef __u32 binder_size_t;
typedef __u32 binder_uintptr_t;
#else
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
#endif

struct binder_write_read {
  binder_size_t write_size;  // bytes to write
  binder_size_t write_consumed;  // bytes consumed by driver
  binder_uintptr_t write_buffer;
  binder_size_t read_size;  // bytes to read
  binder_size_t read_consumed;  // bytes consumed by driver
  binder_uintptr_t read_buffer;
};

struct binder_transaction_data {
  union {
    __u32 handle;  // target descriptor of command transaction
    binder_uintptr_t ptr;  // target descriptor of return transaction
  } target;
  binder_uintptr_t cookie;
  __u32 code;  // transaction command

  __u32 flags;
  pid_t sender_pid;
  uid_t sender_euid; // not used.
  binder_size_t data_size;
  binder_size_t offsets_size;

  // If this transaction is inline, the data immediately follows here;
  // otherwise, it ends with a pointer to the data buffer.
  union {
    struct {
      binder_uintptr_t buffer;
      binder_uintptr_t offsets;
    } ptr;
    __u8 buf[8];
  } data;
};

enum binder_driver_return_protocol {
  BR_ERROR = _IOR('r', 0, int),

  BR_OK = _IO('r', 1),

  BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),

  BR_DEAD_REPLY = _IO('r', 5),

  // Do nothing and examine the next command.
  BR_NOOP = _IO('r', 12),

  BR_FAILED_REPLY = _IO('r', 17),
};

enum binder_driver_command_protocol {
  BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
  BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
};

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, __s32)

#endif  // MYBINDER_BINDER_H_
