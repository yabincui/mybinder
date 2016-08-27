
#include "binder.h"

#include <asm/page_types.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#ifndef SZ_4M
#define SZ_4M  0x400000
#endif

#ifndef SZ_1K
#define SZ_1K 0x400
#endif

enum {
  BINDER_DEBUG_OPEN_CLOSE = 1U << 0,
  BINDER_DEBUG_LOCK = 1U << 1,
  BINDER_DEBUG_PROC_THREAD = 1U << 2,
  BINDER_DEBUG_NODE = 1U << 3,
  BINDER_DEBUG_IOCTL = 1U << 4,
  BINDER_DEBUG_READ_WRITE = 1U << 5,
  BINDER_DEBUG_TRANSACTION = 1U << 6,
  BINDER_DEBUG_BINDER_BUFFER = 1U << 7,
};

static uint32_t binder_debug_mask = BINDER_DEBUG_OPEN_CLOSE | BINDER_DEBUG_LOCK
    | BINDER_DEBUG_PROC_THREAD | BINDER_DEBUG_NODE | BINDER_DEBUG_IOCTL
    | BINDER_DEBUG_READ_WRITE | BINDER_DEBUG_TRANSACTION | BINDER_DEBUG_BINDER_BUFFER;

static struct dentry *binder_debugfs_dir_entry_root;
static struct dentry *binder_debugfs_dir_entry_proc;
static struct binder_node *binder_context_mgr_node;  // protected by main_lock
static int binder_last_id;  // protected by main_lock

static DEFINE_MUTEX(binder_main_lock);
static DEFINE_MUTEX(binder_mmap_lock);  // protect mmap
static HLIST_HEAD(binder_procs);  // protected by binder_main_lock

struct binder_proc {
  struct hlist_node proc_node;  // linked to binder_procs
  int pid;
  struct task_struct *tsk;  // thread opening /dev/binder
  struct dentry *debugfs_entry;  // debugfs file for binder_proc

  // virtual memory space in user space and kernel space.
  struct mm_struct *vma_vm_mm;
  struct vm_area_struct *vma;  // mmap space to send data to user space
  void *buffer;  // memory mapped place in kernel
  size_t buffer_size;
  ptrdiff_t user_buffer_offset;  // buffer + user_buffer_offset is vma->vm_start, memory mapped place in user space

  // physical space.
  struct page **pages;  // used to allocate physical memory

  // allocator of buffer space
  struct list_head buffers;  // list of binder_buffer
  struct rb_root free_buffers;  // rbtree of free binder_buffers

  struct rb_root threads;  // rbtree of binder_thread
  struct rb_root nodes;  // rbtree of binder_node

  struct list_head todo;  // list of binder_transactions
  wait_queue_head_t wait;  // thread belong to this proc can wait for work in todo.
};

struct binder_thread {
  struct binder_proc *proc;
  struct rb_node rb_node;  // linked to proc->threads
  int pid;  // pid of this thread

  struct binder_transaction *transaction_stack;  // transaction list sent by this thread
  struct list_head todo;  // transactions need to be handled by current thread
  wait_queue_head_t wait;  // this can wait for work in todo.
  uint32_t return_error;
};

struct binder_node {
  int debug_id;
  struct rb_node rb_node;  // linked to proc->nodes
  struct binder_proc *proc;
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
};

struct binder_work {
  struct list_head entry;
  enum {
    BINDER_WORK_TRANSACTION = 1,
  } type;
};

struct binder_transaction {
  int debug_id;
  struct binder_work work;  // connect with proc->todo or thread->todo, notify the work type.
  struct binder_thread *from;
  struct binder_transaction *from_parent;  // previous transaction in from->transaction_stack
  struct binder_proc *to_proc;
  struct binder_thread *to_thread;
  struct binder_thread *to_parent;  // connect with to_thread->transaction_stack, waiting to be done by user space
  struct binder_buffer *buffer;  // store data provided by binder_transaction_data
  unsigned need_reply:1;  // need reply for this transaction
  u32 code;
  u32 flags;
};

struct binder_buffer {
  struct list_head entry;  // linked in proc->buffers.
  struct rb_node rb_node;  // linked in proc->free_buffers
  unsigned free:1;
  unsigned allow_user_free:1;

  struct binder_transaction *transaction;
  struct binder_node *target_node;
  size_t data_size;
  size_t offsets_size;
  uint8_t data[0];
};

#define binder_debug(mask, x...) \
  do { \
    if (binder_debug_mask & mask) \
      pr_info(x); \
  } while (0)

#define binder_user_error(x...) \
  pr_info(x)

static inline void binder_lock(const char *tag) {
  binder_debug(BINDER_DEBUG_LOCK, "binder_lock: from %s\n", tag);
  mutex_lock(&binder_main_lock);
}

static inline void binder_unlock(const char *tag) {
  mutex_unlock(&binder_main_lock);
  binder_debug(BINDER_DEBUG_LOCK, "binder_unlock: from %s\n", tag);
}

static unsigned int binder_poll(struct file *filp,
                                struct poll_table_struct *wait) {
  return 0;
}

static struct binder_thread *binder_get_thread(struct binder_proc *proc) {
  struct binder_thread *thread = NULL;
  struct rb_node *parent = NULL;
  struct rb_node **p = &proc->threads.rb_node;

  while (*p) {
    parent = *p;
    thread = rb_entry(parent, struct binder_thread, rb_node);

    if (current->pid < thread->pid)
      p = &(*p)->rb_left;
    else if (current->pid > thread->pid)
      p = &(*p)->rb_right;
    else
      break;
  }
  if (*p == NULL) {
    thread = kzalloc(sizeof(*thread), GFP_KERNEL);
    if (thread == NULL) {
      return NULL;
    }
    thread->proc = proc;
    thread->pid = current->pid;
    INIT_LIST_HEAD(&thread->todo);
    init_waitqueue_head(&thread->wait);
    thread->return_error = BR_OK;
    rb_link_node(&thread->rb_node, parent, p);
    rb_insert_color(&thread->rb_node, &proc->threads);
    binder_debug(BINDER_DEBUG_PROC_THREAD, "create binder_thread: %s, pid %d\n",
                 __func__, thread->pid);
  }
  return thread;
}

static int binder_free_thread(struct binder_proc* proc,
                              struct binder_thread* thread) {
  binder_debug(BINDER_DEBUG_PROC_THREAD, "free binder_thread: %s, pid %d\n",
               __func__, thread->pid);
  rb_erase(&thread->rb_node, &proc->threads);
  kfree(thread);
  return 0;
}

static struct binder_node *binder_new_node(struct binder_proc *proc,
                                          binder_uintptr_t ptr,
                                          binder_uintptr_t cookie) {
  struct rb_node *parent = NULL;
  struct rb_node **p = &proc->nodes.rb_node;
  struct binder_node *node;

  while (*p) {
    parent = *p;
    node = rb_entry(parent, struct binder_node, rb_node);

    if (ptr < node->ptr)
      p = &(*p)->rb_left;
    else if (ptr > node->ptr)
      p = &(*p)->rb_right;
    else
      return NULL;
  }

  node = kzalloc(sizeof(*node), GFP_KERNEL);
  if (node == NULL)
    return NULL;
  node->debug_id = ++binder_last_id;
  rb_link_node(&node->rb_node, parent, p);
  rb_insert_color(&node->rb_node, &proc->nodes);
  node->proc = proc;
  node->ptr = ptr;
  node->cookie = cookie;

  binder_debug(BINDER_DEBUG_NODE, "create binder_node %d: %s, pid %d, ptr %lx\n",
               node->debug_id, __func__, current->pid, (unsigned long)ptr);
  return node;
}

static int binder_node_release(struct binder_node *node) {
  binder_debug(BINDER_DEBUG_NODE, "free binder_node %d: %s, pid %d, ptr %lx\n",
               node->debug_id, __func__, current->pid, (unsigned long)node->ptr);
  rb_erase(&node->rb_node, &node->proc->nodes);
  if (binder_context_mgr_node == node)
    binder_context_mgr_node = NULL;
  kfree(node);
  return 0;
}

static int binder_ioctl_set_ctx_mgr(struct file *filp) {
  int ret = 0;
  struct binder_proc *proc = filp->private_data;

  if (binder_context_mgr_node) {
    pr_err("BINDER_SET_CONTEXT_MGR already set\n");
    ret = -EBUSY;
    goto out;
  }
  binder_context_mgr_node = binder_new_node(proc, 0, 0);
out:
  return ret;
}

static int binder_update_page_range(struct binder_proc *proc, int allocate,
                                    void *start, void *end,
                                    struct vm_area_struct *vma) {
  struct mm_struct *mm = NULL;
  void *page_addr = NULL;
  struct page **page = NULL;
  binder_debug(BINDER_DEBUG_BINDER_BUFFER,
               "%d: %s pages %p-%p\n",
               proc->pid, allocate ? "allocate" : "free", start, end);

  if (end <= start)
    return 0;
  if (vma == NULL) {
    mm = get_task_mm(proc->tsk);
    down_write(&mm->mmap_sem);
    vma = proc->vma;
    if (vma && mm != proc->vma_vm_mm) {
      pr_err("%d: vma_mm and task_mm mismatch\n", proc->pid);
      vma = NULL;
    }
  }

  if (allocate == 0)
    goto free_range;

  if (vma == NULL) {
    pr_err("%d: binder_allocate_buffer failed to map pages in userspace, no vma\n",
           proc->pid);
    goto err_no_vma;
  }

  for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
    int ret = 0;
    page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
    BUG_ON(*page);
    *page = alloc_page(GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
    if (*page == NULL) {
      pr_err("%d: binder_alloc_buffer failed for page at %p\n", proc->pid);
      goto err_alloc_page_failed;
    }
    ret = map_kernel_range_noflush((unsigned long)page_addr, PAGE_SIZE,
                                   PAGE_KERNEL, page);
    flush_cache_vmap((unsigned long)page_addr,
                     (unsigned long)page_addr + PAGE_SIZE);
    if (ret != 1) {
      pr_err("%d: binder_alloc_buffer failed to map page at %p in kernel\n",
             proc->pid, page_addr);
      goto err_map_kernel_failed;
    }
  }

free_range:

  for (page_addr = end - PAGE_SIZE; page_addr >= start;
      page_addr -= PAGE_SIZE) {
    page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
    if (vma)
      zap_page_range(vma, (uintptr_t)page_addr + proc->user_buffer_offset,
                     PAGE_SIZE, NULL);
err_vm_insert_page_failed:
    unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
    __free_page(*page);
err_alloc_page_failed:
    ;
  }

err_no_vma:
  if (mm) {
    up_write(&mm->mmap_sem);
  }
  return -ENOMEM;
}

static struct binder_buffer* binder_alloc_buffer(struct binder_proc *proc,
                                                 size_t data_size,
                                                 size_t offsets_size) {
  struct rb_node *n = proc->free_buffers.rb_node;
  struct binder_buffer *buffer = NULL;
  size_t buffer_size;
  size_t size;
  struct rb_node *best_fit = NULL;
  void *has_page_addr = NULL;
  void *end_page_addr = NULL;

  if (proc->vma == NULL) {
    pr_err("%d: binder_alloc_buffer, no vma\n", proc->pid);
    return NULL;
  }

  size = ALIGN(data_size, sizeof(void*)) + ALIGN(offsets_size, sizeof(void*));
  if (size < data_size || size < offsets_size) {
    binder_user_error("%d: got transaction with invalid size %zd-%zd\n",
                      proc->pid, data_size, offsets_size);
    return NULL;
  }

  while (n) {
    buffer = rb_entry(n, struct binder_buffer, rb_node);
    BUG_ON(!buffer->free);
    buffer_size = binder_buffer_size(proc, buffer);

    if (size < buffer_size) {
      best_fit = n;
      n = n->rb_left;
    } else if (size > buffer_size) {
      n = n->rb_right;
    } else {
      best_fit = n;
      break;
    }
  }
  if (best_fit == NULL) {
    pr_err("%d: binder_alloc_buffer size %zd failed, no address space\n",
           proc->pid, size);
    return NULL;
  }
  if (n == NULL) {
    buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
    buffer_size = binder_buffer_size(proc, buffer);
  }

  binder_debug(BINDER_DEBUG_BINDER_BUFFER,
               "%d: binder_alloc_buffer size %zd got buffer %p size %zd\n",
               proc->pid, size, buffer, buffer_size);

  has_page_addr = (void*)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
  if (n == NULL) {
    if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
      buffer_size = size;  // no room for other buffers
    else
      buffer_size = size + sizeof(struct binder_buffer);
  }

  size_t size;
  struct binder_buffer *buffer = NULL;
  buffer = kzalloc(sizeof(*buffer) + size, GFP_KERNEL);
  buffer->data_size = data_size;
  buffer->offsets_size = offsets_size;
  return buffer;
}

static void binder_make_transaction(struct binder_proc *proc,
                                    struct binder_thread *thread,
                                    struct binder_transaction_data *tr,
                                    bool reply) {
  uint32_t return_error = BR_OK;
  struct binder_node *target_node = NULL;
  struct binder_proc *target_proc = NULL;
  struct list_head *target_list = NULL;  // target_proc's todo list
  wait_queue_head_t *target_wait = NULL;
  struct binder_transaction *t = NULL;
  binder_size_t *offp = NULL;
  if (!reply) {
    if (tr->target.handle) {
      return_error = BR_FAILED_REPLY;
      goto err_invalid_target_handle;
    } else {
      target_node = binder_context_mgr_node;
      if (target_node == NULL) {
        return_error = BR_DEAD_REPLY;
        goto err_no_context_mgr_node;
      }
      target_proc = target_node->proc;
      if (target_proc == NULL) {
        return_error = BR_DEAD_REPLY;
        goto err_dead_binder;
      }
    }
  }
  target_list = &target_proc->todo;
  target_wait = &target_proc->wait;
  t = kzalloc(sizeof(*t), GFP_KERNEL);
  if (t == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_alloc_t_failed;
  }
  t->debug_id = ++binder_last_id;
  binder_debug(BINDER_DEBUG_TRANSACTION,
      "%d:%d BC_TRANSACTION %d -> %d - node %d, data %llx - %llx, size %lld - %lld\n",
      proc->pid, thread->pid, t->debug_id, target_proc->pid,
      (u64)target_node->debug_id,
      (u64)tr->data.ptr.buffer, (u64)tr->data.ptr.offsets,
      (u64)tr->data_size, (u64)tr->offsets_size);
  t->from = thread;
  t->to_proc = target_proc;
  t->to_thread = NULL;
  t->code = tr->code;
  t->flags = tr->flags;
  t->buffer = binder_alloc_buffer(target_proc, tr->data_size, tr->offsets_size);
  if (t->buffer == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_binder_alloc_buf_failed;
  }
  t->buffer->transaction = t;
  t->buffer->target_node = target_node;

  offp = (binder_size_t*)(t->buffer->data +
      ALIGN(tr->data_size, sizeof(void*)));

  if (copy_from_user(t->buffer->data,
                     (const void __user*)(uintptr_t)tr->data.ptr.buffer,
                     tr->data_size)) {
    return_error = BR_FAILED_REPLY;
    goto err_copy_data_failed;
  }
  if (copy_from_user(offp, (const void __user*)(uintptr_t)tr->data.ptr.offsets,
      tr->offsets_size)) {
    return_error = BR_FAILED_REPLY;
    goto err_copy_data_failed;
  }
  if (!IS_ALIGNED(tr->offsets_size, sizeof(binder_size_t))) {
    return_error = BR_FAILED_REPLY;
    goto err_bad_offset;
  }
  t->need_reply = 1;
  t->from_parent = thread->transaction_stack;
  thread->transaction_stack = t;
  t->work.type = BINDER_WORK_TRANSACTION;
  list_add_tail(&t->work.entry, target_list);  // add the transaction to proc->todo.
  if (target_wait)
    wake_up_interruptible(target_wait);  // wait up working thread of target_proc.
  return;

err_bad_offset:
err_copy_data_failed:
  kfree(t->buffer);
err_binder_alloc_buf_failed:
  kfree(t);
err_alloc_t_failed:
err_dead_binder:
err_no_context_mgr_node:
err_invalid_target_handle:
  thread->return_error = return_error;
}

static int binder_thread_write(struct binder_proc *proc,
                               struct binder_thread *thread,
                               binder_uintptr_t binder_buffer,
                               size_t size, binder_size_t *consumed) {
  uint32_t cmd;
  void __user *buffer = (void __user*)(uintptr_t)(binder_buffer);
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  while (ptr < end && thread->return_error == BR_OK) {
    if (get_user(cmd, (uint32_t __user*)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    switch (cmd) {
      case BC_TRANSACTION:
      case BC_REPLY:
        struct binder_transaction_data tr;

        if (copy_from_user(&tr, ptr, sizeof(tr)))
          return -EFAULT;
        ptr += sizeof(tr);
        binder_make_transaction(proc, thread, &tr, cmd == BC_REPLY);
        break;
      default:
        pr_err("%d:%d unknown command %d\n", proc->pid, thread->pid, cmd);
        return -EINVAL;
    }
    *consumed = ptr - buffer;
  }
  return 0;
}

static int binder_has_proc_work(struct binder_proc *proc,
                                struct binder_thread *thread) {
  return !list_empty(&proc->todo);
}

static int binder_has_thread_work(struct binder_thread *thread) {
  return !list_empty(&thread->todo);
}

static int binder_thread_read(struct binder_proc *proc,
                              struct binder_thread *thread,
                              binder_uintptr_t binder_buffer,
                              size_t size, binder_size_t *consumed,
                              bool non_block) {
  void __user *buffer = (void __user*)(uintptr_t)binder_buffer;
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;
  int ret = 0;
  int wait_for_proc_work = 0;

  if (*consumed == 0) {
    if (put_user(BR_NOOP, (uint32_t __user*)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  wait_for_proc_work = thread->transaction_stack == NULL &&
      list_empty(&thread->todo);

  binder_unlock(__func__);

  if (wait_for_proc_work) {
    if (non_block) {
      if (!binder_has_proc_work(proc, thread))
        ret = -EAGAIN;
    } else
      ret = wait_event_freezable_exclusive(proc->wait,
                                           binder_has_proc_work(proc, thread));
  } else {
    if (non_block) {
      if (!binder_has_thread_work(thread))
        ret = -EAGAIN;
    } else
      ret = wait_event_freezable(thread->wait, binder_has_thread_work(thread));
  }

  binder_lock(__func__);

  if (ret)
    return ret;

  while (1) {
    uint32_t cmd = 0;
    struct binder_transaction_data tr;
    struct binder_work *w = NULL;
    struct binder_transaction *t = NULL;

    if (!list_empty(&thread->todo)) {
      w = list_first_entry(&thread->todo, struct binder_work, entry);
    } else if (!list_empty(&proc->todo) && wait_for_proc_work) {
      w = list_first_entry(&proc->todo, struct binder_work, entry);
    } else {
      // no data added
      if (ptr - buffer == 4)
        goto retry;
      break;
    }

    if (end - ptr < sizeof(tr) + 4)
      break;

    switch (w->type) {
      case BINDER_WORK_TRANSACTION:
        t = container_of(w, struct binder_transaction, work);
        break;
    }

    if (!t)
      continue;
    BUG_ON(t->buffer == NULL);
    BUG_ON(t->buffer->target_node == NULL);
    if (t->buffer->target_node) {
      struct binder_node *target_node = t->buffer->target_node;
      // we know the target_node, but we don't know its ptr and cookie,
      // why not set them at binder_make_transaction?
      tr.target.ptr = target_node->ptr;
      tr.cookie = target_node->cookie;
      cmd = BR_TRANSACTION;
    }
    tr.code = t->code;
    tr.flags = t->flags;
    tr.sender_euid = 0;
    if (t->from) {
      struct task_struct *sender = t->from->proc->tsk;
      tr.sender_pid = task_tgid_nr_ns(sender, task_active_pid_ns(current));
    } else {
      tr.sender_pid = 0;
    }

    tr.data_size = t->buffer->data_size;
    tr.offsets_size = t->buffer->offsets_size;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)t->buffer->data;
    tr.data.ptr.offsets = tr.data.ptr.buffer +
        ALIGN(t->buffer->data_size, sizeof(void*));

    if (put_user(cmd, (uint32_t __user*)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    if (copy_to_user(ptr, &tr, sizeof(tr)))
      return -EFAULT;
    ptr += sizeof(tr);

    binder_debug(BINDER_DEBUG_TRANSACTION,
                 "%d:%d %s, %d %d:%d, cmd %d size %zd-%zd, ptr %llx-%llx\n",
                 proc->pid, thread->pid,
                 (cmd == BR_TRANSACTION) ? "BR_TRANSACTION" : "BR_REPLY",
                 t->debug_id, t->from ? t->from->proc->pid : 0,
                 t->from ? t->from->pid : 0, cmd,
                 t->buffer->data_size, t->buffer->offsets_size,
                 (u64)tr.data.ptr.buffer, (u64)tr.data.ptr.offsets);
    list_del(&t->work.entry);
    t->buffer->allow_user_free = 1;
    if (cmd == BR_TRANSACTION) {
      t->to_parent = thread->transaction_stack;
      t->to_thread = thread;
      thread->transaction_stack = t;
    }
  }

done:
  *consumed = ptr - buffer;
  return 0;
}

static int binder_ioctl_write_read(struct file *filp, unsigned int cmd,
                                   unsigned long arg,
                                   struct binder_thread *thread) {
  int ret = 0;
  struct binder_proc *proc = filp->private_data;
  unsigned int size = _IOC_SIZE(cmd);
  void __user *ubuf = (void __user *)arg;
  struct binder_write_read bwr;

  if (size != sizeof(struct binder_write_read)) {
    ret = -EINVAL;
    goto out;
  }
  if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
    ret = -EFAULT;
    goto out;
  }
  binder_debug(BINDER_DEBUG_READ_WRITE,
               "%d:%d write %lld at %llx, read %lld at %llx\n",
               proc->pid, thread->pid,
               (u64)bwr.write_size, (u64)bwr.write_buffer,
               (u64)bwr.read_size, (u64)bwr.read_buffer);

  if (bwr.write_size > 0) {
    ret = binder_thread_write(proc, thread, bwr.write_buffer,
                              bwr.write_size, &bwr.write_consumed);
    if (ret < 0) {
      bwr.read_consumed = 0;
      if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
        ret = -EFAULT;
      goto out;
    }
  }
  if (bwr.read_size > 0) {
    ret = binder_thread_read(proc, thread, bwr.read_buffer,
                             bwr.read_size, &bwr.read_consumed,
                             filp->f_flags & O_NONBLOCK);
  }
  binder_debug(BINDER_DEBUG_READ_WRITE,
               "%d:%d wrote %lld of %lld, read return %lld of %lld\n",
               proc->pid, thread->pid,
               (u64)bwr.write_consumed, (u64)bwr.write_size,
               (u64)bwr.read_consumed, (u64)bwr.read_size);
  if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
    ret = -EFAULT;
    goto out;
  }
out:
  return ret;
}

static long binder_ioctl(struct file *filp, unsigned int cmd,
                         unsigned long arg) {
  int ret = 0;
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  binder_lock(__func__);
  thread = binder_get_thread(proc);
  if (thread == NULL) {
    ret = -ENOMEM;
    goto err;
  }

  switch (cmd) {
    case BINDER_SET_CONTEXT_MGR:
      ret = binder_ioctl_set_ctx_mgr(filp);
      if (ret)
        goto err;
      break;
    case BINDER_WRITE_READ:
      ret = binder_ioctl_write_read(filp, cmd, arg, thread);
      if (ret)
        goto err;
      break;
  }

err:
  binder_unlock(__func__);
  binder_debug(BINDER_DEBUG_IOCTL, "binder_ioctl: cmd %u, ret %d\n", cmd, ret);
  return ret;
}

static size_t binder_buffer_size(struct binder_proc *proc,
                                 struct binder_buffer *buffer) {
  if (list_is_last(&buffer->entry, &proc->buffers))
    return proc->buffer + proc->buffer_size - (void*)buffer->data;
  return (size_t)list_entry(buffer->entry.next, struct binder_buffer, entry) -
      (size_t)buffer->data;
}

static void binder_insert_free_buffer(struct binder_proc *proc,
                                      struct binder_buffer *new_buffer) {
  struct rb_node **p = &proc->free_buffers.rb_node;
  struct rb_node *parent = NULL;
  struct binder_buffer *buffer = NULL;
  size_t new_buffer_size = 0;
  size_t buffer_size = 0;

  BUG_ON(!new_buffer->free);
  new_buffer_size = binder_buffer_size(proc, new_buffer);

  binder_debug(BINDER_DEBUG_BINDER_BUFFER,
               "%d: add free buffer, size %zd, at %p\n",
               proc->pid, new_buffer_size, new_buffer);

  while (*p) {
    parent = *p;
    buffer = rb_entry(parent, struct binder_buffer, rb_node);
    BUG_ON(!buffer->free);

    buffer_size = binder_buffer_size(proc, buffer);
    if (new_buffer_size < buffer_size)
      p = &parent->rb_left;
    else
      p = &parent->rb_right;
  }
  rb_link_node(&new_buffer->rb_node, parent, p);
  rb_insert_color(&new_buffer->rb_node, &proc->free_buffers);
}

static void binder_vma_open(struct vm_area_struct *vma) {
  struct binder_proc *proc = vma->vm_private_data;
  binder_debug(BINDER_DEBUG_OPEN_CLOSE,
               "%d open vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",
               proc->pid, vma->vm_start, vma->vm_end,
               (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
               (unsigned long)pgprot_val(vma->vm_page_prot));
}

static void binder_vma_close(struct vm_area_struct *vma) {
  struct binder_proc *proc = vma->vm_private_data;
  binder_debug(BINDER_DEBUG_OPEN_CLOSE,
               "%d close vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",
               proc->pid, vma->vm_start, vma->vm_end,
               (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
               (unsigned long)pgprot_val(vma->vm_page_prot));
  proc->vma = NULL;
  proc->vma_vm_mm = NULL;
}

static int binder_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {
  return VM_FAULT_SIGBUS;
}

static const struct vm_operations_struct binder_vm_ops = {
    .open = binder_vma_open,
    .close = binder_vma_close,
    .fault = binder_vm_fault,
};

static int binder_mmap(struct file *filp, struct vm_area_struct *vma) {
  struct binder_proc *proc = filp->private_data;
  const char *failure_string = NULL;
  int ret = 0;
  struct vm_struct *area = NULL;
  struct binder_buffer *buffer = NULL;

  if (proc->tsk != current)
    return -EINVAL;
  if ((vma->vm_end - vma->vm_start) > SZ_4M)
    vma->vm_end = vma->vm_start + SZ_4M;

  binder_debug(BINDER_DEBUG_OPEN_CLOSE,
               "binder_mmap: %d %lx-%lx (%ld K) vma %lx, pagep %lx\n",
               proc->pid, vma->vm_start, vma->vm_end,
               (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
               (unsigned long)pgprot_val(vma->vm_page_prot));

  if (vma->vm_flags & VM_WRITE) {
    ret = -EPERM;
    failure_string = "bad vm_flags";
    goto err_bad_arg;
  }
  vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;

  mutex_lock(&binder_mmap_lock);
  if (proc->buffer) {
    ret = -EBUSY;
    failure_string = "already mapped";
    goto err_already_mapped;
  }

  area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
  if (area == NULL) {
    ret = -ENOMEM;
    failure_string = "get_vm_area";
    goto err_get_vm_area_failed;
  }
  proc->buffer = area->addr;
  proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;

  mutex_unlock(&binder_mmap_lock);

  proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
  if (proc->pages == NULL) {
    ret = -ENOMEM;
    failure_string = "alloc page array";
    goto err_alloc_pages_failed;
  }
  proc->buffer_size = vma->vm_end - vma->vm_start;
  vma->vm_ops = &binder_vm_ops;
  vma->vm_private_data = proc;
  buffer = proc->buffer;
  buffer->free = 1;
  binder_insert_free_buffer(proc, buffer);
  barrier();  // why a barrier here ?
  proc->vma = vma;
  proc->vma_vm_mm = vma->vm_mm;
  return 0;

err_alloc_pages_failed:
  mutex_lock(&binder_mmap_lock);
  vfree(proc->buffer);
  proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
  mutex_unlock(&binder_mmap_lock);
err_bad_arg:
  pr_err("binder_mmap: %d %lx-%lx %s failed %d\n",
         proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
  return ret;
}

static int binder_proc_show(struct seq_file *m, void *unused) {
  struct binder_proc *itr;
  struct binder_proc *proc = m->private;
  bool valid_proc = false;

  binder_lock(__func__);

  hlist_for_each_entry(itr, &binder_procs, proc_node) {
    if (itr == proc) {
      valid_proc = true;
      break;
    }
  }
  if (valid_proc) {
    seq_puts(m, "binder proc state:\n");
    seq_printf(m, "proc %d\n", proc->pid);
  }
  binder_unlock(__func__);
  return 0;
}

static int binder_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, binder_proc_show, inode->i_private);
}

static const struct file_operations binder_proc_fops = {
    .owner = THIS_MODULE,
    .open = binder_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int binder_open(struct inode *nodp, struct file *filp) {
  struct binder_proc *proc;
  binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_open: %d:%d\n",
               current->group_leader->pid, current->pid);

  proc = kzalloc(sizeof(*proc), GFP_KERNEL);
  if (proc == NULL)
    return -ENOMEM;
  get_task_struct(current);
  proc->pid = current->pid;
  proc->tsk = current;
  proc->vma_vm_mm = current->mm;
  INIT_LIST_HEAD(&proc->todo);
  init_waitqueue_head(&proc->wait);
  binder_lock(__func__);
  hlist_add_head(&proc->proc_node, &binder_procs);
  binder_unlock(__func__);
  filp->private_data = proc;

  binder_debug(BINDER_DEBUG_PROC_THREAD, "create binder_proc: %s, pid %d\n",
               __func__, current->pid);

  if (binder_debugfs_dir_entry_proc) {
    char strbuf[11];
    snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
    proc->debugfs_entry = debugfs_create_file(strbuf, S_IRUGO,
        binder_debugfs_dir_entry_proc, proc, &binder_proc_fops);
  }
  return 0;
}

static void release_binder_proc(struct binder_proc *proc) {
  struct rb_node *n;
  binder_lock(__func__);

  while ((n = rb_first(&proc->threads))) {
    struct binder_thread *thread;
    thread = rb_entry(n, struct binder_thread, rb_node);
    binder_free_thread(proc, thread);
  }

  while ((n = rb_first(&proc->nodes))) {
    struct binder_node *node;
    node = rb_entry(n, struct binder_node, rb_node);
    binder_node_release(node);
  }

  if (proc->pages) {
    kfree(proc->pages);
    vfree(proc->buffer);
  }

  binder_debug(BINDER_DEBUG_PROC_THREAD, "free binder_proc: %s, pid %d\n",
               __func__, proc->pid);

  put_task_struct(proc->tsk);
  kfree(proc);
  binder_unlock(__func__);

}

static int binder_release(struct inode *nodp, struct file *filp) {
  struct binder_proc *proc = filp->private_data;

  binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_close: %d:%d\n",
               current->group_leader->pid, current->pid);

  debugfs_remove(proc->debugfs_entry);
  release_binder_proc(proc);
  return 0;
}

static int binder_flush(struct file *filp, fl_owner_t id) {
  return 0;
}

static const struct file_operations binder_fops = {
    .owner = THIS_MODULE,
    .poll = binder_poll,
    .unlocked_ioctl = binder_ioctl,
    .compat_ioctl = binder_ioctl,
    .mmap = binder_mmap,
    .open = binder_open,
    .flush = binder_flush,
    .release = binder_release,
};

static struct miscdevice binder_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "binder",
    .fops = &binder_fops,
};

static int binder_state_show(struct seq_file *m, void *unused) {
  seq_puts(m, "binder state:\n");
  seq_puts(m, "binder state end\n");
  return 0;
}

static int binder_state_open(struct inode *inode, struct file *file) {
  return single_open(file, binder_state_show, inode->i_private);
}

const struct file_operations binder_state_fops = {
    .owner = THIS_MODULE,
    .open = binder_state_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int init_binder(void) {
	int ret;

	pr_err("init_binder\n");
	binder_debugfs_dir_entry_root = debugfs_create_dir("mybinder", NULL);
	pr_info("binder_debugfs_dir_entry_root = %p\n", binder_debugfs_dir_entry_root);
	if (binder_debugfs_dir_entry_root)
		binder_debugfs_dir_entry_proc = debugfs_create_dir("proc",
						 binder_debugfs_dir_entry_root);
	ret = misc_register(&binder_miscdev);
	if (ret != 0) {
	  pr_err("misc_register return %d\n", ret);
	}
	if (binder_debugfs_dir_entry_root) {
		debugfs_create_file("state",
				    S_IRUGO,
				    binder_debugfs_dir_entry_root,
				    NULL,
				    &binder_state_fops);
	}
	return ret;
}

static void cleanup_binder(void) {
  pr_err("cleanup_binder\n");

  misc_deregister(&binder_miscdev);
  debugfs_remove_recursive(binder_debugfs_dir_entry_root);

}

module_init(init_binder);
module_exit(cleanup_binder);

MODULE_LICENSE("GPL v2");
