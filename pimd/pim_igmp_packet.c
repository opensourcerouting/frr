// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IGMP packet handling implementation.
 * Copyright (C) 2022-2023 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#include "lib/zebra.h"

#include "lib/checksum.h"

#include "pimd/pimd.h"
#include "pimd/pim_iface.h"
#include "pimd/pim_igmp_packet.h"

/** IPv4 header + router alert header size. */
const size_t ipv4_router_alert_size = sizeof(struct ipv4_header) + sizeof(struct ipv4_router_alert);

/**
 * Minimum expected MTU to generate the multicast packets is the IPv6
 * recommendation of 1280 bytes (otherwise the underlying layer must
 * provide fragmentation/assembly).
 *
 * See "RFC 2460 Section 5. Packet Size Issues".
 */
const size_t multicast_minimum_mtu = 1280;

/** Find or allocate new join group parameters entry. */
static struct igmp_packet_group_params *
igmp_packet_params_get_group(struct igmp_packet_params *params, const struct in_addr *group)
{
	struct igmp_packet_group_params *group_params;

	SLIST_FOREACH (group_params, &params->groups, entry)
		if (group_params->group.s_addr == group->s_addr)
			return group_params;

	group_params = XCALLOC(MTYPE_TMP, sizeof(*group_params));
	group_params->group = *group;
	SLIST_INSERT_HEAD(&params->groups, group_params, entry);
	return group_params;
}

/** Adds new source if it doesn't exist. */
static void igmp_packet_group_params_add_source(struct igmp_packet_group_params *group_params,
						const struct in_addr *source)
{
	struct igmp_packet_group_source_params *source_params;

	/* Note star source and don't add it. */
	if (source->s_addr == INADDR_ANY) {
		group_params->star_source = true;
		return;
	}

	SLIST_FOREACH (source_params, &group_params->sources, entry)
		if (group_params->group.s_addr == source->s_addr)
			return;

	source_params = XCALLOC(MTYPE_TMP, sizeof(*source_params));
	source_params->source = *source;
	SLIST_INSERT_HEAD(&group_params->sources, source_params, entry);
	group_params->sources_number += 1;
}

/**
 * Generates IPv4 header for IGMP packet:
 * IPv4 with protocol set to IGMP, ToS set to required value and router alert.
 *
 * Don't forget to set `total_length` and `checksum` after appending the
 * payload.
 */
static void ipv4_igmp_header(struct ipv4_header *ipv4, const struct in_addr *source)
{
	struct ipv4_router_alert *router_alert;

	ipv4_set_version(ipv4);
	ipv4_set_header_length(ipv4, ipv4_router_alert_size);
	ipv4->tos = IPV4_TOS_INTERNET_PROTOCOL;
	ipv4->ttl = 1;
	ipv4->protocol = IPPROTO_IGMP;
	ipv4->source = *source;
	ipv4->destination.s_addr = htonl(IGMP_ALL_ROUTERS_ADDRESS);

	router_alert = (struct ipv4_router_alert *)((uint8_t *)ipv4 + sizeof(struct ipv4_header));
	router_alert->identifier = htons(IPV4_ROUTER_ALERT_IDENTIFIER);
	router_alert->value = htons(IPV4_ROUTER_ALERT_VALUE_EXAMINE);
}

/**
 * Generates IGMP version 3 join packet (membership report). After the packet
 * is initialized multicast records can be added with
 * `igmpv3_join_packet_add_record` and finally be ready to send with
 * `igmpv3_join_packet_finish`.
 *
 * TODO:
 * Handle IGMP record splitting, see "RFC 3376 Section 4.2.16. Membership
 * Report Size".
 */
static void igmpv3_join_packet_init(struct igmp_packet *packet, const struct in_addr *source)
{
	struct ipv4_header *ipv4 = (struct ipv4_header *)packet->data;
	struct igmpv3_membership_report *join_packet;

	memset(packet->data, 0, packet->size);
	ipv4_igmp_header(ipv4, source);
	join_packet = (struct igmpv3_membership_report *)(packet->data + ipv4_header_length(ipv4));
	join_packet->header.type = IGMP_TYPE_MEMBERSHIP_REPORT_V3;
	packet->current_record = (uint8_t *)&join_packet->records[0];

	packet->current_size = ipv4_header_length(ipv4) + sizeof(struct igmpv3_membership_report);
}

/**
 * Prepares IGMPv3 packet to be ready to be sent. This function truncates
 * the payload size to its real value and calculates the checksum.
 */
static void igmpv3_join_packet_finish(struct igmp_packet *packet)
{
	struct ipv4_header *ipv4 = (struct ipv4_header *)packet->data;
	struct igmpv3_membership_report *join_packet =
		(struct igmpv3_membership_report *)(packet->data + ipv4_header_length(ipv4));

	ipv4->total_length = htons((uint16_t)packet->current_size);
	ipv4->checksum = (uint16_t)in_cksum(ipv4, ipv4_header_length(ipv4));
	join_packet->header.checksum =
		(uint16_t)in_cksum(join_packet,
				   (uint16_t)packet->current_size - ipv4_header_length(ipv4));

	packet->size = packet->current_size;
}

/**
 * Appends a multicast record to an IGMPv3 membership report packet.
 *
 * **NOTES**
 * 1. Before calling this function the buffer needs to be prepared with
 *    `igmpv3_join_packet_init`.
 * 2. If `source_params_head` is not `NULL` it means we are encoding a
 *    split group. See "RFC 3376 Section 4.2.16. Membership Report Size"
 *    for more details.
 *
 * \param packet where to encode multicast record.
 * \param group_params group to encode.
 * \param source_params_head group source list start.
 * \param join whether to generate a join or leave.
 * \returns next source to be encoded or `NULL`.
 */
static const struct igmp_packet_group_source_params *igmpv3_packet_add_record(
	struct igmp_packet *packet, const struct igmp_packet_group_params *group_params,
	const struct igmp_packet_group_source_params *source_params_head, bool join)
{
	const struct igmp_packet_group_source_params *source_params = NULL;
	const struct ipv4_header *ipv4 = (struct ipv4_header *)packet->data;
	struct igmpv3_membership_report *igmp_packet =
		(struct igmpv3_membership_report *)(packet->data + ipv4_header_length(ipv4));
	struct igmpv3_multicast_record *record =
		(struct igmpv3_multicast_record *)packet->current_record;
	const uint16_t records_number = ntohs(igmp_packet->records_number);
	size_t record_size = sizeof(struct igmpv3_multicast_record);

	igmp_packet->records_number = htons(records_number + 1);
	record->multicast_address = group_params->group;
	if (join) {
		if (group_params->star_source || group_params->sources_number == 0)
			record->type = MULTICAST_MODE_CHANGE_TO_EXCLUDE;
		else
			record->type = MULTICAST_MODE_ALLOW_NEW_SOURCES;
	} else {
		if (group_params->star_source || group_params->sources_number == 0)
			record->type = MULTICAST_MODE_CHANGE_TO_INCLUDE;
		else
			record->type = MULTICAST_MODE_BLOCK_OLD_SOURCES;
	}

	if (!group_params->star_source) {
		size_t index = 0;

		if (!source_params_head)
			source_params_head = SLIST_FIRST(&group_params->sources);

		for (source_params = source_params_head; source_params;
		     source_params = SLIST_NEXT(source_params, entry)) {
			if ((packet->current_size + record_size + sizeof(uint32_t)) > packet->size)
				break;

			record->sources[index] = source_params->source;
			record_size += sizeof(uint32_t);
			index += 1;
		}

		record->sources_number = htons((uint16_t)index);
	} else
		record->sources_number = 0;

	packet->current_record += record_size;
	packet->current_size += record_size;

	if (record->type == MULTICAST_MODE_IS_EXCLUDE ||
	    record->type == MULTICAST_MODE_CHANGE_TO_EXCLUDE)
		return NULL;

	return source_params;
}

/** Generate join packets for IGMP version 3. */
static struct igmp_packet_list *igmpv3_generate_packets(const struct igmp_packet_params *params)
{
	const struct igmp_packet_group_params *group_params;
	struct igmp_packet_list *packets;

	packets = XCALLOC(MTYPE_TMP, sizeof(*packets));

	/*
	 * Iterate over groups and generate the multicast records. If a group
	 * is not type EXCLUDE and not all sources fit the same packet then we
	 * need to generate a new packet and fill the remaining sources.
	 */
	SLIST_FOREACH (group_params, &params->groups, entry) {
		const struct igmp_packet_group_source_params *source_params = NULL;

		do {
			struct igmp_packet *packet;

			packet = XCALLOC(MTYPE_TMP, sizeof(*packet) + params->maximum_size);
			packet->size = params->maximum_size;
			SLIST_INSERT_HEAD(packets, packet, entry);

			igmpv3_join_packet_init(packet, &params->source);
			source_params = igmpv3_packet_add_record(packet, group_params,
								 source_params, params->join);
			igmpv3_join_packet_finish(packet);
		} while (source_params);
	}

	return packets;
}

/** IGMP version 1 or 2 membership join packet generator. */
static void igmp_generate_packet(enum igmp_version version, const struct in_addr *source,
				 const struct in_addr *group, uint8_t *data, size_t datalen)
{
	const size_t igmp_header_size = sizeof(struct igmp_membership_report);
	struct ipv4_header *ipv4 = (struct ipv4_header *)data;
	struct igmp_membership_report *join_packet;

	assert(version == IGMP_VERSION_1 || version == IGMP_VERSION_2);
	assert(datalen >= ipv4_router_alert_size + igmp_header_size);

	ipv4_igmp_header(ipv4, source);

	join_packet = (struct igmp_membership_report *)(data + ipv4_header_length(ipv4));
	join_packet->header.type = version == IGMP_VERSION_2 ? IGMP_TYPE_MEMBERSHIP_REPORT_V2
							     : IGMP_TYPE_MEMBERSHIP_REPORT_V1;
	join_packet->group = *group;

	join_packet->header.checksum = (uint16_t)in_cksum(join_packet, igmp_header_size);
}

struct igmp_packet_params *
pim_interface_generate_igmp_static_params(const struct interface *interface, bool join,
					  const struct in_addr *source, const struct in_addr *group)
{
	const struct pim_interface *pim_interface = interface->info;
	struct igmp_packet_group_params *group_params;
	const struct gm_join *igmp_join;
	struct igmp_packet_params *params;
	struct listnode *node;

	assert(pim_interface != NULL);

	params = XCALLOC(MTYPE_TMP, sizeof(*params));
	params->version = (enum igmp_version)pim_interface->igmp_version;
	params->source = pim_interface->primary_address;
	params->join = join;
	/*
	 * To avoid crashes we'll always use a minimum MTU even if the
	 * interface doesn't support it. See `multicast_minimum_mtu`
	 * comment for more information.
	 */
	if (interface->mtu < multicast_minimum_mtu) {
		zlog_warn("Interface %s MTU is too low (%d bytes)", interface->name,
			  interface->mtu);
		params->maximum_size = multicast_minimum_mtu;
	} else
		params->maximum_size = interface->mtu;

	for (ALL_LIST_ELEMENTS_RO(pim_interface->gm_join_list, node, igmp_join)) {
		if (group && group->s_addr != igmp_join->group_addr.s_addr)
			continue;
		if (source && source->s_addr != igmp_join->source_addr.s_addr)
			continue;

		group_params = igmp_packet_params_get_group(params, &igmp_join->group_addr);
		igmp_packet_group_params_add_source(group_params, &igmp_join->source_addr);
	}

	return params;
}

void igmp_join_params_free(struct igmp_packet_params *params)
{
	while (!SLIST_EMPTY(&params->groups)) {
		struct igmp_packet_group_params *group_params = SLIST_FIRST(&params->groups);

		while (!SLIST_EMPTY(&group_params->sources)) {
			struct igmp_packet_group_source_params *source_params =
				SLIST_FIRST(&group_params->sources);

			SLIST_REMOVE(&group_params->sources, source_params,
				     igmp_packet_group_source_params, entry);
			XFREE(MTYPE_TMP, source_params);
		}

		SLIST_REMOVE(&params->groups, group_params, igmp_packet_group_params, entry);
		XFREE(MTYPE_TMP, group_params);
	}

	XFREE(MTYPE_TMP, params);
}


struct igmp_packet_list *igmp_generate_packets(const struct igmp_packet_params *params)
{
	struct igmp_packet_group_params *group_params;
	struct igmp_packet_list *packets;
	struct igmp_packet *packet;

	/* No groups to join. */
	if (SLIST_EMPTY(&params->groups))
		return NULL;

	/* Special IGMPv3 handling: multiple groups on same message. */
	if (params->version == IGMP_VERSION_3)
		return igmpv3_generate_packets(params);

	/* IGMP version 1 or 2: one group per packet and no sources. */
	packets = XCALLOC(MTYPE_TMP, sizeof(*packets));

	SLIST_FOREACH (group_params, &params->groups, entry) {
		const size_t ipv4_total_length = ipv4_router_alert_size +
						 sizeof(struct igmp_membership_report);
		struct ipv4_header *ipv4;

		packet = XCALLOC(MTYPE_TMP, sizeof(*packet) + ipv4_total_length);
		packet->size = ipv4_total_length;
		igmp_generate_packet(params->version, &params->source, &group_params->group,
				     packet->data, packet->size);

		ipv4 = (struct ipv4_header *)packet->data;
		ipv4->total_length = htons((uint16_t)ipv4_total_length);
		ipv4->checksum = (uint16_t)in_cksum(ipv4, ipv4_header_length(ipv4));

		SLIST_INSERT_HEAD(packets, packet, entry);
	}

	return packets;
}

void igmp_packet_list_free(struct igmp_packet_list *packets)
{
	struct igmp_packet *packet;

	while (!SLIST_EMPTY(packets)) {
		packet = SLIST_FIRST(packets);
		SLIST_REMOVE(packets, packet, igmp_packet, entry);
		XFREE(MTYPE_TMP, packet);
	}

	XFREE(MTYPE_TMP, packets);
}
