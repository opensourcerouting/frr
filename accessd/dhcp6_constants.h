/*
 * DO NOT EDIT - this file is autogenerated from dhcpv6-parameters.xml
 *
 * download a fresh version instead and run dhcp6_constants.py
 */
/* clang-format off */


/* Message Types */
#ifndef DH6MSG
#define DH6MSG(name, val, ...)
#endif
/* 0: Reserved */
DH6MSG(SOLICIT,				   1)
DH6MSG(ADVERTISE,			   2)
DH6MSG(REQUEST,				   3)
DH6MSG(CONFIRM,				   4)
DH6MSG(RENEW,				   5)
DH6MSG(REBIND,				   6)
DH6MSG(REPLY,				   7)
DH6MSG(RELEASE,				   8)
DH6MSG(DECLINE,				   9)
DH6MSG(RECONFIGURE,			  10)
DH6MSG(INFORMATION_REQUEST,		  11)
DH6MSG(RELAY_FORW,			  12)
DH6MSG(RELAY_REPL,			  13)
DH6MSG(LEASEQUERY,			  14)
DH6MSG(LEASEQUERY_REPLY,		  15)
DH6MSG(LEASEQUERY_DONE,			  16)
DH6MSG(LEASEQUERY_DATA,			  17)
DH6MSG(RECONFIGURE_REQUEST,		  18)
DH6MSG(RECONFIGURE_REPLY,		  19)
DH6MSG(DHCPV4_QUERY,			  20)
DH6MSG(DHCPV4_RESPONSE,			  21)
DH6MSG(ACTIVELEASEQUERY,		  22)
DH6MSG(STARTTLS,			  23)
DH6MSG(BNDUPD,				  24)
DH6MSG(BNDREPLY,			  25)
DH6MSG(POOLREQ,				  26)
DH6MSG(POOLRESP,			  27)
DH6MSG(UPDREQ,				  28)
DH6MSG(UPDREQALL,			  29)
DH6MSG(UPDDONE,				  30)
DH6MSG(CONNECT,				  31)
DH6MSG(CONNECTREPLY,			  32)
DH6MSG(DISCONNECT,			  33)
DH6MSG(STATE,				  34)
DH6MSG(CONTACT,				  35)
#undef DH6MSG

/* Option Codes */
#ifndef DH6OPT
#define DH6OPT(name, val, ...)
#endif
/* 0: Reserved */
DH6OPT(CLIENTID,			   1, 0, 1)
DH6OPT(SERVERID,			   2, 0, 1)
DH6OPT(IA_NA,				   3, 0, 0)
DH6OPT(IA_TA,				   4, 0, 0)
DH6OPT(IAADDR,				   5, 0, 0)
DH6OPT(ORO,				   6, 0, 1)
DH6OPT(PREFERENCE,			   7, 0, 1)
DH6OPT(ELAPSED_TIME,			   8, 0, 1)
DH6OPT(RELAY_MSG,			   9, 0, 1)
/* 10: Unassigned */
DH6OPT(AUTH,				  11, 0, 1)
DH6OPT(UNICAST,				  12, 0, 1)
DH6OPT(STATUS_CODE,			  13, 0, 1)
DH6OPT(RAPID_COMMIT,			  14, 0, 1)
DH6OPT(USER_CLASS,			  15, 0, 1)
DH6OPT(VENDOR_CLASS,			  16, 0, 0)
DH6OPT(VENDOR_OPTS,			  17, 1, 0)
DH6OPT(INTERFACE_ID,			  18, 0, 1)
DH6OPT(RECONF_MSG,			  19, 0, 1)
DH6OPT(RECONF_ACCEPT,			  20, 0, 1)
DH6OPT(SIP_SERVER_D,			  21, 1, 1)
DH6OPT(SIP_SERVER_A,			  22, 1, 1)
DH6OPT(DNS_SERVERS,			  23, 1, 1)
DH6OPT(DOMAIN_LIST,			  24, 1, 1)
DH6OPT(IA_PD,				  25, 0, 0)
DH6OPT(IAPREFIX,			  26, 0, 0)
DH6OPT(NIS_SERVERS,			  27, 1, 1)
DH6OPT(NISP_SERVERS,			  28, 1, 1)
DH6OPT(NIS_DOMAIN_NAME,			  29, 1, 1)
DH6OPT(NISP_DOMAIN_NAME,		  30, 1, 1)
DH6OPT(SNTP_SERVERS,			  31, 1, 1)
DH6OPT(INFORMATION_REFRESH_TIME,	  32, 1, 1)
DH6OPT(BCMCS_SERVER_D,			  33, 1, 1)
DH6OPT(BCMCS_SERVER_A,			  34, 1, 1)
/* 35: Unassigned */
DH6OPT(GEOCONF_CIVIC,			  36, 1, 1)
DH6OPT(REMOTE_ID,			  37, 0, 1)
DH6OPT(SUBSCRIBER_ID,			  38, 0, 1)
DH6OPT(CLIENT_FQDN,			  39, 1, 1)
DH6OPT(PANA_AGENT,			  40, 1, 1)
DH6OPT(NEW_POSIX_TIMEZONE,		  41, 1, 1)
DH6OPT(NEW_TZDB_TIMEZONE,		  42, 1, 1)
DH6OPT(ERO,				  43, 0, 1)
DH6OPT(LQ_QUERY,			  44, 0, 1)
DH6OPT(CLIENT_DATA,			  45, 0, 1)
DH6OPT(CLT_TIME,			  46, 0, 1)
DH6OPT(LQ_RELAY_DATA,			  47, 0, 1)
DH6OPT(LQ_CLIENT_LINK,			  48, 0, 1)
DH6OPT(MIP6_HNIDF,			  49, 1, 1)
DH6OPT(MIP6_VDINF,			  50, 1, 1)
DH6OPT(V6_LOST,				  51, 1, 1)
DH6OPT(CAPWAP_AC_V6,			  52, 1, 1)
DH6OPT(RELAY_ID,			  53, 0, 1)
DH6OPT(IPV6_ADDRESS_MOS,		  54, 1, 1)
DH6OPT(IPV6_FQDN_MOS,			  55, 1, 1)
DH6OPT(NTP_SERVER,			  56, 1, 1)
DH6OPT(V6_ACCESS_DOMAIN,		  57, 1, 1)
DH6OPT(SIP_UA_CS_LIST,			  58, 1, 1)
DH6OPT(OPT_BOOTFILE_URL,		  59, 1, 1)
DH6OPT(OPT_BOOTFILE_PARAM,		  60, 1, 1)
DH6OPT(CLIENT_ARCH_TYPE,		  61, 0, 1)
DH6OPT(NII,				  62, 1, 1)
DH6OPT(GEOLOCATION,			  63, 1, 1)
DH6OPT(AFTR_NAME,			  64, 1, 1)
DH6OPT(ERP_LOCAL_DOMAIN_NAME,		  65, 1, 1)
DH6OPT(RSOO,				  66, 0, 1)
DH6OPT(PD_EXCLUDE,			  67, 1, 1)
DH6OPT(VSS,				  68, 0, 1)
DH6OPT(MIP6_IDINF,			  69, 1, 1)
DH6OPT(MIP6_UDINF,			  70, 1, 1)
DH6OPT(MIP6_HNP,			  71, 1, 1)
DH6OPT(MIP6_HAA,			  72, 1, 1)
DH6OPT(MIP6_HAF,			  73, 1, 1)
DH6OPT(RDNSS_SELECTION,			  74, 1, 1)
DH6OPT(KRB_PRINCIPAL_NAME,		  75, 1, 1)
DH6OPT(KRB_REALM_NAME,			  76, 1, 1)
DH6OPT(KRB_DEFAULT_REALM_NAME,		  77, 1, 1)
DH6OPT(KRB_KDC,				  78, 1, 1)
DH6OPT(CLIENT_LINKLAYER_ADDR,		  79, 0, 1)
DH6OPT(LINK_ADDRESS,			  80, 0, 1)
DH6OPT(RADIUS,				  81, 0, 1)
DH6OPT(SOL_MAX_RT,			  82, 1, 1)
DH6OPT(INF_MAX_RT,			  83, 1, 1)
DH6OPT(ADDRSEL,				  84, 1, 1)
DH6OPT(ADDRSEL_TABLE,			  85, 1, 1)
DH6OPT(V6_PCP_SERVER,			  86, 1, 0)
DH6OPT(DHCPV4_MSG,			  87, 0, 1)
DH6OPT(DHCP4_O_DHCP6_SERVER,		  88, 1, 1)
DH6OPT(S46_RULE,			  89, 0, 0)
DH6OPT(S46_BR,				  90, 1, 0)
DH6OPT(S46_DMR,				  91, 0, 1)
DH6OPT(S46_V4V6BIND,			  92, 0, 1)
DH6OPT(S46_PORTPARAMS,			  93, 0, 1)
DH6OPT(S46_CONT_MAPE,			  94, 1, 0)
DH6OPT(S46_CONT_MAPT,			  95, 1, 1)
DH6OPT(S46_CONT_LW,			  96, 1, 1)
DH6OPT(4RD,				  97, 1, 1)
DH6OPT(4RD_MAP_RULE,			  98, 1, 1)
DH6OPT(4RD_NON_MAP_RULE,		  99, 1, 1)
DH6OPT(LQ_BASE_TIME,			 100, 0, 1)
DH6OPT(LQ_START_TIME,			 101, 0, 1)
DH6OPT(LQ_END_TIME,			 102, 0, 1)
DH6OPT(DHCP_CAPTIVE_PORTAL,		 103, 1, 1)
DH6OPT(MPL_PARAMETERS,			 104, 1, 0)
DH6OPT(ANI_ATT,				 105, 0, 1)
DH6OPT(ANI_NETWORK_NAME,		 106, 0, 1)
DH6OPT(ANI_AP_NAME,			 107, 0, 1)
DH6OPT(ANI_AP_BSSID,			 108, 0, 1)
DH6OPT(ANI_OPERATOR_ID,			 109, 0, 1)
DH6OPT(ANI_OPERATOR_REALM,		 110, 0, 1)
DH6OPT(S46_PRIORITY,			 111, 1, 1)
DH6OPT(MUD_URL_V6,			 112, 0, 1)
DH6OPT(V6_PREFIX64,			 113, 1, 0)
DH6OPT(F_BINDING_STATUS,		 114, 0, 1)
DH6OPT(F_CONNECT_FLAGS,			 115, 0, 1)
DH6OPT(F_DNS_REMOVAL_INFO,		 116, 0, 1)
DH6OPT(F_DNS_HOST_NAME,			 117, 0, 1)
DH6OPT(F_DNS_ZONE_NAME,			 118, 0, 1)
DH6OPT(F_DNS_FLAGS,			 119, 0, 1)
DH6OPT(F_EXPIRATION_TIME,		 120, 0, 1)
DH6OPT(F_MAX_UNACKED_BNDUPD,		 121, 0, 1)
DH6OPT(F_MCLT,				 122, 0, 1)
DH6OPT(F_PARTNER_LIFETIME,		 123, 0, 1)
DH6OPT(F_PARTNER_LIFETIME_SENT,		 124, 0, 1)
DH6OPT(F_PARTNER_DOWN_TIME,		 125, 0, 1)
DH6OPT(F_PARTNER_RAW_CLT_TIME,		 126, 0, 1)
DH6OPT(F_PROTOCOL_VERSION,		 127, 0, 1)
DH6OPT(F_KEEPALIVE_TIME,		 128, 0, 1)
DH6OPT(F_RECONFIGURE_DATA,		 129, 0, 1)
DH6OPT(F_RELATIONSHIP_NAME,		 130, 0, 1)
DH6OPT(F_SERVER_FLAGS,			 131, 0, 1)
DH6OPT(F_SERVER_STATE,			 132, 0, 1)
DH6OPT(F_START_TIME_OF_STATE,		 133, 0, 1)
DH6OPT(F_STATE_EXPIRATION_TIME,		 134, 0, 1)
DH6OPT(RELAY_PORT,			 135, 0, 1)
DH6OPT(V6_SZTP_REDIRECT,		 136, 1, 1)
DH6OPT(S46_BIND_IPV6_PREFIX,		 137, 1, 1)
DH6OPT(IA_LL,				 138, 0, 0)
DH6OPT(LLADDR,				 139, 0, 0)
DH6OPT(SLAP_QUAD,			 140, 0, 1)
DH6OPT(V6_DOTS_RI,			 141, 1, 1)
DH6OPT(V6_DOTS_ADDRESS,			 142, 1, 1)
DH6OPT(IPV6_ADDRESS_ANDSF,		 143, 1, 1)
#undef DH6OPT

/* Status Codes */
#ifndef DH6ST
#define DH6ST(name, val, ...)
#endif
DH6ST(SUCCESS,				   0)
DH6ST(UNSPECFAIL,			   1)
DH6ST(NOADDRSAVAIL,			   2)
DH6ST(NOBINDING,			   3)
DH6ST(NOTONLINK,			   4)
DH6ST(USEMULTICAST,			   5)
DH6ST(NOPREFIXAVAIL,			   6)
DH6ST(UNKNOWNQUERYTYPE,			   7)
DH6ST(MALFORMEDQUERY,			   8)
DH6ST(NOTCONFIGURED,			   9)
DH6ST(NOTALLOWED,			  10)
DH6ST(QUERYTERMINATED,			  11)
DH6ST(DATAMISSING,			  12)
DH6ST(CATCHUPCOMPLETE,			  13)
DH6ST(NOTSUPPORTED,			  14)
DH6ST(TLSCONNECTIONREFUSED,		  15)
DH6ST(ADDRESSINUSE,			  16)
DH6ST(CONFIGURATIONCONFLICT,		  17)
DH6ST(MISSINGBINDINGINFORMATION,	  18)
DH6ST(OUTDATEDBINDINGINFORMATION,	  19)
DH6ST(SERVERSHUTTINGDOWN,		  20)
DH6ST(DNSUPDATENOTSUPPORTED,		  21)
DH6ST(EXCESSIVETIMESKEW,		  22)
#undef DH6ST

/* DUIDs */
#ifndef DUID
#define DUID(name, val, ...)
#endif
DUID(LLT,				   1)
DUID(EN,				   2)
DUID(LL,				   3)
DUID(UUID,				   4)
#undef DUID
