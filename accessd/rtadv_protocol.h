/*
 * Copyright (C) 2022 David Lamparter
 * Copyright (C) 2005 6WIND <jean-mickael.guerin@6wind.com>
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ACCESSD_RTADV_PROTOCOL_H
#define _ACCESSD_RTADV_PROTOCOL_H

#define RTADV_MAX_RTR_ADV_INTERVAL 600000
#define RTADV_MAX_REACHABLE_TIME 3600000
#define RTADV_DFLT_HOPLIMIT 64 /* 64 hops */
#define RTADV_MAX_RTRLIFETIME 9000 /* 2.5 hours */

#ifndef ND_RA_FLAG_HOME_AGENT
#define ND_RA_FLAG_HOME_AGENT 0x20
#endif

#define RTADV_MAX_HALIFETIME 65520 /* 18.2 hours */
#define RTADV_PREF_MEDIUM 0x0 /* Per RFC4191. */
#define RTADV_MAX_ENCODED_DOMAIN_NAME 255

#define RTADV_PREFIX_DFLT_VALID 2592000
#define RTADV_PREFIX_DFLT_PREFERRED 604800

#ifndef ND_OPT_PI_FLAG_RADDR
#define ND_OPT_PI_FLAG_RADDR         0x20
#endif

#ifndef ND_OPT_ADV_INTERVAL
#define ND_OPT_ADV_INTERVAL	7   /* Adv Interval Option */
#endif
#ifndef ND_OPT_HA_INFORMATION
#define ND_OPT_HA_INFORMATION	8   /* HA Information Option */
#endif
#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
#endif
#ifndef ND_OPT_DNSSL
#define ND_OPT_DNSSL 31
#endif

#ifndef HAVE_STRUCT_ND_OPT_ADV_INTERVAL
struct nd_opt_adv_interval { /* Advertisement interval option */
	uint8_t nd_opt_ai_type;
	uint8_t nd_opt_ai_len;
	uint16_t nd_opt_ai_reserved;
	uint32_t nd_opt_ai_interval;
} __attribute__((__packed__));
#else
#ifndef HAVE_STRUCT_ND_OPT_ADV_INTERVAL_ND_OPT_AI_TYPE
/* fields may have to be renamed */
#define nd_opt_ai_type		nd_opt_adv_interval_type
#define nd_opt_ai_len		nd_opt_adv_interval_len
#define nd_opt_ai_reserved	nd_opt_adv_interval_reserved
#define nd_opt_ai_interval	nd_opt_adv_interval_ival
#endif
#endif

#ifndef HAVE_STRUCT_ND_OPT_HOMEAGENT_INFO
struct nd_opt_homeagent_info { /* Home Agent info */
	uint8_t nd_opt_hai_type;
	uint8_t nd_opt_hai_len;
	uint16_t nd_opt_hai_reserved;
	uint16_t nd_opt_hai_preference;
	uint16_t nd_opt_hai_lifetime;
} __attribute__((__packed__));
#endif

#ifndef HAVE_STRUCT_ND_OPT_RDNSS
struct nd_opt_rdnss { /* Recursive DNS server option [RFC8106 5.1] */
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved;
	uint32_t nd_opt_rdnss_lifetime;
	/* Followed by one or more IPv6 addresses */
} __attribute__((__packed__));
#endif

#ifndef HAVE_STRUCT_ND_OPT_DNSSL
struct nd_opt_dnssl { /* DNS search list option [RFC8106 5.2] */
	uint8_t nd_opt_dnssl_type;
	uint8_t nd_opt_dnssl_len;
	uint16_t nd_opt_dnssl_reserved;
	uint32_t nd_opt_dnssl_lifetime;
	/*
	 * Followed by one or more domain names encoded as in [RFC1035 3.1].
	 * Multiple domain names are concatenated after encoding. In any case,
	 * the result is zero-padded to a multiple of 8 octets.
	 */
} __attribute__((__packed__));
#endif

#endif /* _ACCESSD_RTADV_PROTOCOL_H */
