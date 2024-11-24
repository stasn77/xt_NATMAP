#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
# define PDE_DATA pde_data
#endif

#if  LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
#define PROC_OPS(s,o,r,w,l,d) static const struct file_operations s = { \
	.open		= o, \
	.read		= r, \
	.write		= w, \
	.llseek		= l, \
	.release	= d \
}
#else
#define PROC_OPS(s,o,r,w,l,d) static const struct proc_ops s = { \
	.proc_open	= o , \
	.proc_read	= r , \
	.proc_write	= w , \
	.proc_release	= d \
}
#endif

#if  LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static const struct file_operations natmap_fops;
#else
static const struct proc_ops natmap_fops;
#endif
