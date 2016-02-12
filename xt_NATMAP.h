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

#ifndef _XT_NATMAP_H
#define _XT_NATMAP_H

#include <linux/types.h>

enum {
	XT_NATMAP_ADDR		= 1 << 0,
	XT_NATMAP_PRIO		= 1 << 1,
	XT_NATMAP_MARK		= 1 << 2,
	XT_NATMAP_MODE		= XT_NATMAP_ADDR|XT_NATMAP_PRIO|XT_NATMAP_MARK,
	XT_NATMAP_PERS		= 1 << 3,
	XT_NATMAP_DROP		= 1 << 4,

	XT_NATMAP_CGNT		= 1 << 5,
	XT_NATMAP_2WAY		= 1 << 6,

	XT_NATMAP_NAME_LEN	= 32,
};

struct xt_natmap_tginfo {
	struct nf_nat_range range;
	__u8 mode;
	bool pre_routing;
	char name[XT_NATMAP_NAME_LEN];

	/* values below only used in kernel */
	struct xt_natmap_htable *ht;
};
#endif /* _XT_NATMAP_H */
