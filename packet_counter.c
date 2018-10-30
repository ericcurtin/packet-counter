#include <linux/cpufreq.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/usb.h>

static LIST_HEAD(my_list);

struct my_entry {
	struct list_head list;
	char ip[40];
	unsigned long long count;
};

static unsigned postroute_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct iphdr *hdr = (struct iphdr *)skb_network_header(skb);
	struct my_entry *me;
	struct list_head *l;
	char this_ip[40];
	int exist = 0;

	pr_info("%pI4", &hdr->daddr);
	sprintf(this_ip, "%pI4", &hdr->daddr);

	list_for_each (l, &my_list) {
		struct my_entry *i = list_entry(l, struct my_entry, list);
		if (!strcmp(i->ip, this_ip)) {
			++i->count;
			exist = 1;
			me = i;
			break;
		}
	}

	if (!exist) {
		struct my_entry *m_list =
			kmalloc(sizeof(struct my_entry), GFP_KERNEL);
		m_list->count = 1;
		strcpy(m_list->ip, this_ip);
		list_add(&m_list->list, &my_list);
		me = m_list;
	}

	pr_info("Dest=%s %llu", this_ip, me->count);

	return NF_ACCEPT;
}

static struct nf_hook_ops hooks[] __read_mostly = { {
	.hook = (nf_hookfn *)postroute_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST,
} };

static int __init my_init(void)
{
	struct net *n;
	pr_info("load module %p\n", my_init);

	for_each_net (n) {
		nf_register_net_hooks(n, hooks, 1);
	}

	pr_info("finished loading module %p\n", my_init);

	return 0;
}

static void __exit my_exit(void)
{
	struct net *n;
	struct list_head *list; /* pointer to list head object */
	struct list_head *tmp; /* temporary list head for safe deletion */

	pr_info("unload module: '%p'\n", my_exit);

	for_each_net (n) {
		nf_unregister_net_hooks(n, hooks, 1);
	}

	list_for_each_safe (list, tmp, &my_list) {
		struct my_entry *me = list_entry(list, struct my_entry, list);
		list_del(&me->list);
		kfree(me);
	}

	pr_info("finished unloading module: '%p'\n", my_exit);
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL v2");
