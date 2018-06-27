/* portchange.c
 * 
 * Kai Luo (kailuo.nk@gmail.com)
 *
 * All rights reserved.
 *
 */

#include <linux/module.h>    /* Needed by all modules */
#include <linux/kernel.h>    /* Needed for KERN_INFO */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/udp.h>
#include <linux/syscalls.h>

#include "portchange.h"

#define PC_MAX_ARRAY_NUM 4096
#define PC_HASH_SEED 0xFADEFACE

#define CRYSTAL_MAJOR 234
#define CRYSTAL_DEV "cystal_dev"

asmlinkage long (*orig_mknod)(const char __user *filename,
                              umode_t mode, unsigned dev);

#if 0
#define DEBUG_PORTCHANGE(...) do { \
    printk(__VA_ARGS__);     \
} while(0)
#else
#define DEBUG_PORTCHANGE(...)
#endif

struct pc_request {
    struct list_head list;
    struct file *file;
    unsigned short port;
    unsigned int array_num;
    unsigned short port_array[0];
};

static spinlock_t pc_lock;
static struct list_head pc_list;

int pc_request_register(struct file *file, unsigned long arg)
{
    struct pc_request *request, *r; 
    int i;
    int err = 0;
    struct pc_req_register_s reg;
    
    if (copy_from_user(&reg, (struct pc_req_register_s *)arg,
                       sizeof(struct pc_req_register_s))) {
        return -EFAULT;
    }

    if (reg.key != PC_REQUEST_KEY) {
        return -EINVAL;
    }

    if ((reg.array_num == 0) || (reg.array_num > PC_MAX_ARRAY_NUM)) {
        return -EINVAL;
    }

    request = kmalloc(sizeof(struct pc_request) +
                      sizeof(unsigned short) * reg.array_num, GFP_KERNEL);
    if (request == NULL) {
        return -ENOMEM;
    }

    if (copy_from_user(request->port_array, reg.port_array,
                       sizeof(unsigned short) * reg.array_num)) {
        err = -EFAULT;
        goto out_free_request;
    }

    for (i = 0; i < reg.array_num; i++) {
        request->port_array[i] = htons(reg.port_array[i]);
    }

    request->file = file;
    request->port = htons(reg.port);
    request->array_num = reg.array_num;

    spin_lock_bh(&pc_lock);

    list_for_each_entry(r, &pc_list, list) {
        if (r->port == request->port) {
            spin_unlock_bh(&pc_lock);
            err = -EEXIST;
            goto out_free_request;
        }
    }

    list_add_rcu(&request->list, &pc_list);

    spin_unlock_bh(&pc_lock);

    DEBUG_PORTCHANGE("PORTCHANGE: add port %u\n", reg.port);

    return 0;

out_free_request:
    kfree(request);
    return err;
}

int pc_request_unregister(struct file *file, unsigned long arg)
{
    unsigned short port = (unsigned short) arg;
    struct pc_request *r, *tmp;

    DEBUG_PORTCHANGE("PORTCHANGE: try to delete port %u\n", port);

    port = htons(port);

    spin_lock_bh(&pc_lock);

    list_for_each_entry_safe(r, tmp, &pc_list, list) {
        if ((r->port == port) && (file == r->file)) {
            list_del_rcu(&r->list);

            spin_unlock_bh(&pc_lock);

            synchronize_rcu();

            kfree(r);

            DEBUG_PORTCHANGE("PORTCHANGE: delete port %u\n", ntohs(port));

            return 0;
        }
    }

    spin_unlock_bh(&pc_lock);

    return -EINVAL;
}

void pc_request_clean(struct file *file)
{
    struct pc_request *r, *tmp;

begin:
    spin_lock_bh(&pc_lock);

    list_for_each_entry_safe(r, tmp, &pc_list, list) {
        if (file == r->file) {
            list_del_rcu(&r->list);

            spin_unlock_bh(&pc_lock);

            synchronize_rcu();

            DEBUG_PORTCHANGE("PORTCHANGE: delete port %u\n", ntohs(r->port));

            kfree(r);

            goto begin;
        }
    }

    spin_unlock_bh(&pc_lock);
}

static struct nf_hook_ops pc_ops_in;
static struct nf_hook_ops pc_ops_out;

unsigned int change_port_in(const struct nf_hook_ops *ops, 
                            struct sk_buff *skb,
                            const struct net_device *in,
                            const struct net_device *out,
#ifndef __GENKSYMS__
                            const struct nf_hook_state *state
#else
                            int (*okfn)(struct sk_buff *)
#endif
                           )
{
    struct iphdr *iph;
    struct udphdr *uh;
    struct pc_request *r;
    unsigned int hash;

    if (unlikely(!skb)) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (unlikely(!iph)) {
        return NF_ACCEPT;  
    }

    if (iph->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    uh = udp_hdr(skb);
    if (!uh) {
        return NF_ACCEPT;
    }

    rcu_read_lock();

    list_for_each_entry_rcu(r, &pc_list, list) {
        if (uh->dest == r->port) {
            goto found; 
        }
    }

    goto out;

found:
    DEBUG_PORTCHANGE("PORTCHANGE: dest = %u\n", ntohs(uh->dest));

    hash = jhash_1word(iph->saddr, PC_HASH_SEED) ^ uh->source;

    hash %= r->array_num; 

    uh->dest = r->port_array[hash];

    DEBUG_PORTCHANGE("PORTCHANGE: saddr = %x, source = %u, new_dest = %u, hash = %u\n",
                     iph->saddr, ntohs(uh->source), ntohs(uh->dest), hash);
out:
    rcu_read_unlock();

    return NF_ACCEPT;
}

unsigned int change_port_out(const struct nf_hook_ops *ops,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
#ifndef __GENKSYMS__
                             const struct nf_hook_state *state
#else
                             int (*okfn)(struct sk_buff *)
#endif
                            )
{
    struct iphdr *iph;
    struct udphdr *uh;
    struct pc_request *r;
    int i;

    if (unlikely(!skb)) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (unlikely(!iph)) {
        return NF_ACCEPT;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    uh = udp_hdr(skb);
    if (!uh) {
        return NF_ACCEPT;
    }

    rcu_read_lock();

    list_for_each_entry_rcu(r, &pc_list, list) {
        for (i = 0; i < r->array_num; i++) {
            if (r->port_array[i] == uh->source) {
                goto found;
            }
        }
    }

    goto out;

found:
    DEBUG_PORTCHANGE("PORTCHANGE: source = %u, new = %u\n", ntohs(uh->source), ntohs(r->port));

    uh->source = r->port;
out:
    rcu_read_unlock();

    return NF_ACCEPT;
}

static long crystal_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
    long result = -EINVAL;

    switch (cmd)
    {
    case PC_REQUEST_REGISTER:
        result = pc_request_register(file, arg);
        break;
    case PC_REQUEST_UNREGISTER:
        result = pc_request_unregister(file, arg);
        break;
    default:
        break;
    }

    return result;
}

#ifdef CONFIG_COMPAT
long crystal_compat_ioctl(struct file * file, unsigned int cmd, unsigned long arg)
{
    return crystal_ioctl(file, cmd, arg);
}
#endif

static int crystal_open(struct inode *inode, struct file *filp)
{
    __module_get(THIS_MODULE);

    return 0;
}

static int crystal_release(struct inode *inode, struct file *file)
{
    pc_request_clean(file);

    module_put(THIS_MODULE);

    return 0;
}

struct file_operations crystal_fops = {
    open: crystal_open,
    release: crystal_release,
    unlocked_ioctl: crystal_ioctl,
#ifdef CONFIG_COMPAT
    compat_ioctl:   crystal_compat_ioctl
#endif
};

int __init init_module(void)
{
    int err;
    unsigned long sym_addr;
    mm_segment_t oldfs;

    printk(KERN_INFO "portchange init\n");

    sym_addr = kallsyms_lookup_name("sys_mknod");
    if (sym_addr == 0) {
        printk(KERN_INFO "can not find sys_mknod\n");
        return -1;
    }

    orig_mknod = sym_addr;

    INIT_LIST_HEAD(&pc_list);

    spin_lock_init(&pc_lock);

    err = register_chrdev(CRYSTAL_MAJOR, CRYSTAL_DEV, &crystal_fops);
    if (err == 0) {
        oldfs = get_fs();
        set_fs(KERNEL_DS);

        err = orig_mknod(DEVICE_NAME, S_IFCHR|S_IRUGO|S_IWUGO, new_encode_dev(MKDEV(CRYSTAL_MAJOR, 0)));

        set_fs(oldfs);

        if (err != 0) {
            if (err == -EEXIST) {
                err = 0;
            } else {
                printk(KERN_EMERG "portchange init: failed mknod() [%d]\n", err);
                unregister_chrdev(CRYSTAL_MAJOR, CRYSTAL_DEV);
            }
        }
    } else {
        printk(KERN_EMERG "portchange init: failed register_chrdev() [%d]\n", err);
    }

    if (err) {
        printk(KERN_EMERG "portchange init: cannot install crystal dev [%d]\n", err);
        return err;
    }

    pc_ops_in.hook = change_port_in;
    pc_ops_in.hooknum = NF_INET_LOCAL_IN;
    pc_ops_in.pf = PF_INET;
    pc_ops_in.priority = NF_IP_PRI_LAST;

    pc_ops_out.hook = change_port_out;
    pc_ops_out.hooknum = NF_INET_LOCAL_OUT;
    pc_ops_out.pf = PF_INET;
    pc_ops_out.priority = NF_IP_PRI_LAST;

    nf_register_hook(&pc_ops_in);
    nf_register_hook(&pc_ops_out);

    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "portchange cleanup\n");

    nf_unregister_hook(&pc_ops_in);
    nf_unregister_hook(&pc_ops_out);

    (void) unregister_chrdev(CRYSTAL_MAJOR, CRYSTAL_DEV);
}

MODULE_LICENSE("GPL");
