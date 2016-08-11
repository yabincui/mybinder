
#include "binder.h"

#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>

enum {
  BINDER_DEBUG_OPEN_CLOSE = 1U << 0,
  BINDER_DEBUG_LOCK = 1U << 1,
  BINDER_DEBUG_PROC_THREAD = 1U << 2,
  BINDER_DEBUG_NODE = 1U << 3,
  BINDER_DEBUG_IOCTL = 1U << 4,
};

static uint32_t binder_debug_mask = BINDER_DEBUG_OPEN_CLOSE | BINDER_DEBUG_LOCK
    | BINDER_DEBUG_PROC_THREAD | BINDER_DEBUG_NODE | BINDER_DEBUG_IOCTL;

static struct dentry *binder_debugfs_dir_entry_root;
static struct dentry *binder_debugfs_dir_entry_proc;
static struct binder_node *binder_context_mgr_node;

DEFINE_MUTEX(binder_main_lock);
static HLIST_HEAD(binder_procs);  // protected by binder_main_lock

struct binder_proc {
  struct hlist_node proc_node;  // linked to binder_procs
  int pid;
  struct task_struct *tsk;  // thread opening /dev/binder
  struct dentry *debugfs_entry;  // debugfs file for binder_proc

  struct rb_root threads;  // rbtree of binder_thread
  struct rb_root nodes;  // rbtree of binder_node
};

struct binder_thread {
  struct binder_proc *proc;
  struct rb_node rb_node;  // linked to proc->threads
  int pid;  // pid of this thread
};

struct binder_node {
  struct rb_node rb_node;  // linked to proc->nodes
  struct binder_proc *proc;
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
};

#define binder_debug(mask, x...) \
  do { \
    if (binder_debug_mask & mask) \
      pr_info(x); \
  } while (0)

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
  rb_link_node(&node->rb_node, parent, p);
  rb_insert_color(&node->rb_node, &proc->nodes);
  node->proc = proc;
  node->ptr = ptr;
  node->cookie = cookie;

  binder_debug(BINDER_DEBUG_NODE, "create binder_node: %s, pid %d, ptr %lx\n",
               __func__, current->pid, (unsigned long)ptr);
  return node;
}

static int binder_node_release(struct binder_node *node) {
  binder_debug(BINDER_DEBUG_NODE, "free binder_node: %s, pid %d, ptr %lx\n",
               __func__, current->pid, (unsigned long)node->ptr);
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
  }

err:
  binder_unlock(__func__);
  binder_debug(BINDER_DEBUG_IOCTL, "binder_ioctl: cmd %u, ret %d\n", cmd, ret);
  return ret;
}

static int binder_mmap(struct file *filp, struct vm_area_struct *vma) {
  return -EINVAL;
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
