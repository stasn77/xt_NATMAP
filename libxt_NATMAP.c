/*
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _DEFAULT_SOURCE 1
#define _ISOC99_SOURCE 1
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <arpa/inet.h>
#include <linux/netfilter/nf_nat.h>
#include "xt_NATMAP.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif


static void natmap_help(void)
{
	printf(
"natmap match options:\n"
"  --nm-name <name>   Name of the natmap set to be used.\n"
"                     DEFAULT will be used if none given.\n"
"  --nm-mode <mode>   Address match: prio, mark or addr (default).\n"
"  --nm-pers          Persistent mode when flushing NAT tables.\n"
"  --nm-drop          Hotdrop mode for not-matching packets.\n"
"  --nm-cgnt          Carrier-Grade NAT variant of postnat/cidr mode.\n"
"xt_NATMAP by: Stasn77 <stasn77@gmail.com>.\n");
}

enum {
	O_NAME,
	O_MODE,
	O_PERS,
	O_DROP,
	O_CGNT,
};

#define s struct xt_natmap_tginfo
static const struct xt_option_entry natmap_opts[] = {
	{.name = "nm-name", .id = O_NAME, .type = XTTYPE_STRING,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, name), .min = 1},
	{.name = "nm-mode", .id = O_MODE, .type = XTTYPE_STRING},
	{.name = "nm-pers", .id = O_PERS, .type = XTTYPE_NONE},
	{.name = "nm-drop", .id = O_DROP, .type = XTTYPE_NONE},
	{.name = "nm-cgnt", .id = O_CGNT, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};
#undef s

static int parse_mode(uint8_t *mode, const char *option_arg)
{
	if (strcasecmp("prio", option_arg) == 0) {
		*mode &= ~XT_NATMAP_ADDR;
		*mode |= XT_NATMAP_PRIO;
	} else if (strcasecmp("mark", option_arg) == 0) {
		*mode &= ~XT_NATMAP_ADDR;
		*mode |= XT_NATMAP_MARK;
	} else if (strcasecmp("addr", option_arg) == 0)
		*mode |= XT_NATMAP_ADDR;
	else
		return -1;
	return 0;
}

static void print_mode(uint8_t mode)
{
	/* SRC is primary and exclusive with SKB*/
	if (mode & XT_NATMAP_PRIO)
		fputs("prio", stdout);
	else if (mode & XT_NATMAP_MARK)
		fputs("mark", stdout);
	else if (mode & XT_NATMAP_ADDR)
		fputs("addr", stdout);
}

static void natmap_parse(struct xt_option_call *cb)
{
	struct xt_natmap_tginfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_MODE:
		if (parse_mode(&info->mode, cb->arg) < 0)
			xtables_param_act(XTF_BAD_VALUE, "nm",
			    "--nm-mode", cb->arg);
		break;
	case O_PERS:
		info->mode |= XT_NATMAP_PERS;
		break;
	case O_DROP:
		info->mode |= XT_NATMAP_DROP;
		break;
	case O_CGNT:
		info->mode |= XT_NATMAP_CGNT;
		break;
	}
}

static void natmap_init(struct xt_entry_target *target)
{
	struct xt_natmap_tginfo *tginfo = (struct xt_natmap_tginfo *)target->data;
	struct nf_nat_range *mr = &tginfo->range;

	mr->flags |= NF_NAT_RANGE_MAP_IPS;
	strncpy(tginfo->name, "DEFAULT", XT_NATMAP_NAME_LEN);
	tginfo->name[XT_NATMAP_NAME_LEN - 1] = '\0';
	tginfo->mode |= XT_NATMAP_ADDR;
}

static void natmap_print(const void *ip, const struct xt_entry_target *target,
int numeric)
{
	const struct xt_natmap_tginfo *tginfo = (const void *)target->data;

	fputs(" NATMAP:", stdout);
	printf(" name=%s", tginfo->name);
	fputs(" mode=", stdout);
	print_mode(tginfo->mode);
	if (tginfo->mode & XT_NATMAP_PERS)
		printf(" pers");
	if (tginfo->mode & XT_NATMAP_DROP)
		printf(" drop");
	if (tginfo->mode & XT_NATMAP_CGNT)
		printf(" cgnt");
}

static void natmap_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_natmap_tginfo *info = (const void *)target->data;

	if (strcmp("DEFAULT", info->name))
		printf(" --nm-name %s", info->name);
	if (info->mode & XT_NATMAP_PERS)
		printf(" --nm-pers");
	if (info->mode & XT_NATMAP_DROP)
		printf(" --nm-drop");
	if (info->mode & XT_NATMAP_CGNT)
		printf(" --nm-cgnt");
	if (info->mode & XT_NATMAP_MODE) {
		fputs(" --nm-mode ", stdout);
		print_mode(info->mode);
	}

}

static struct xtables_target natmap_tg_reg[] = {
	{
		.name		= "NATMAP",
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.size		= XT_ALIGN(sizeof(struct xt_natmap_tginfo)),
		.userspacesize	= offsetof(struct xt_natmap_tginfo, ht),
		.help		= natmap_help,
		.init		= natmap_init,
		.print		= natmap_print,
		.save		= natmap_save,
		.x6_options	= natmap_opts,
		.x6_parse	= natmap_parse,
	},
};

void _init(void)
{
	xtables_register_targets(natmap_tg_reg, ARRAY_SIZE(natmap_tg_reg));
}
