#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28) && LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static inline u_int8_t xt_family(const struct xt_action_param *par)
{
	return par->family;
}
static inline const struct net_device *xt_in(const struct xt_action_param *par)
{
	return par->in;
}
static inline const struct net_device *xt_out(const struct xt_action_param *par)
{
	return par->out;
}
static inline unsigned int xt_hooknum(const struct xt_action_param *par)
{
	return par->hooknum;
}
#endif