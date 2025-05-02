#ifndef _FC_MS_H
#define _FC_MS_H

#include <linux/types.h>

/*
 * Fibre Channel - Generic Services - 7
 * From T11.org FC-GS-7 Rev 10.0 February 2012
 */

/*
 * Common-transport sub-types for the Management Server
 */

#define FC_MS_SUBTYPE_CONF    1 /* Fabric Configuration Server */
#define FC_MS_SUBTYPE_UNZONE  2 /* Unzoned Name server */
#define FC_MS_SUBTYPE_ZONE    3 /* Fabric Zone server */
#define FC_MS_SUBTYPE_FDMI    4 /* Fabric Device Management Interface */

/*
 * Management Server Requests
 */
enum fc_ms_zs_req {
	FC_MS_ZS_GFEZ	= 0x0142, /* Get Fabric Enhanced Zoning */
	FC_MS_ZS_SFEZ	= 0x0242, /* Set Fabric Enhanced Zoning */
	/* Basic Zoning Management Commands */
	FC_MS_ZS_GZC	= 0x0100, /* Get Capabilities */
	FC_MS_ZS_GEST	= 0x0111, /* Get Zone Set List */
	FC_MS_ZS_GZD	= 0x0112, /* Get Zone List */
	FC_MS_ZS_GZM	= 0x0114, /* Get Zone Member List */
	FC_MS_ZS_GAZS	= 0x0115, /* Get Active Zone List */
	FC_MS_ZS_GZS	= 0x0116, /* Get Zone Set */
	FC_MS_ZS_GAR	= 0x0117, /* Get Activation Results */
	FC_MS_ZS_ADZS	= 0x0200, /* Add Zone Set */
	FC_MS_ZS_AZSD	= 0x0201, /* Activate Zone Set Direct */
	FC_MS_ZS_AZS	= 0x0202, /* Activate Zone Set */
	FC_MS_ZS_DZS	= 0x0203, /* Deactivate Zone Set */
	FC_MS_ZS_AZM	= 0x0204, /* Add Zone Members */
	FC_MS_ZS_AZD	= 0x0205, /* Add Zone */
	FC_MS_ZS_RSM	= 0x0300, /* Remove Zone Members */
	FC_MS_ZS_RZD	= 0x0301, /* Remove Zone */
	FC_MS_ZS_RZS	= 0x0302, /* Remove Zone Set */
	/* Enhanced Zoning */
	FC_MS_ZS_GZA	= 0x0120, /* Get Zone Attribute Object Name */
	FC_MS_ZS_GZAB	= 0x0121, /* Get Zone Attribute Block */
	FC_MS_ZS_GZSE	= 0x0122, /* Get Zone Set List - Enhanced */
	FC_MS_ZS_GZDE	= 0x0123, /* Get Zone List - Enhanced */
	FC_MS_ZS_GZME	= 0x0124, /* Get Zone Member List - Enhanced */
	FC_MS_ZS_GZAL	= 0x0125, /* Get Zone Attribute Object List */
	FC_MS_ZS_GAZSE	= 0x0126, /* Get Active Zone Set - Enhanced */
	FC_MS_SZ_GAL	= 0x0128, /* Get Alias List */
	FC_MS_SZ_GAM	= 0x0129, /* Get Alias Member List */
	FC_MS_SZ_GAPZ	= 0x012A, /* Get Active Peer Zone */
	FC_MS_SZ_AZSDE	= 0x0211, /* Activate Zone Set Direct - Enhanced */
	FC_MS_SZ_AZSE	= 0x0212, /* Activate Zone Set - Enhanced */
	FC_MS_SZ_DZSE	= 0x0213, /* Deactivate Zone Set - Enhanced */
	FC_MS_SZ_CZS	= 0x0220, /* Create Zone Set */
	FC_MS_SZ_AZ	= 0x0221, /* Add Zones */
	FC_MS_SZ_AZME	= 0x0224, /* Add Zone Members - Enhanced */
	FC_MS_SZ_CZ	= 0x0225, /* Create Zone */
	FC_MS_SZ_CZA	= 0x0226, /* Create Zone Attribute Object */
	FC_MS_SZ_SZA	= 0x0227, /* Set Zone Attribute Object Name */
	FC_MS_SZ_SZAB	= 0x0228, /* Set Zone Attribute BlockZone */
	FC_MS_SZ_CA	= 0x0229, /* Create Alias */
	FC_MS_SZ_AAM	= 0x022A, /* Add Alias Members */
	FC_MS_SZ_AAPZ	= 0x022B, /* Add/Replace Active Peer Zone */
	FC_MS_SZ_RZ	= 0x0321, /* Remove Zones */
	FC_MS_SZ_RZME	= 0x0324, /* Remove Zone Members - Enhanced */
	FC_MS_SZ_RAPZ	= 0x0325, /* Remove Active Peer Zone */
	FC_MS_SZ_RAM	= 0x032A, /* Remove Alias Members */
	FC_MS_SZ_DLZS	= 0x032B, /* Delete Zone Set */
	FC_MS_SZ_DLZ	= 0x032C, /* Delete Zone */
	FC_MS_SZ_DLA	= 0x032D, /* Delete Alias */
	FC_MS_SZ_DLZA	= 0x032E, /* Delete Zone Attribute Object */
	/* Server session commands */
	FC_MS_ZS_SSB	= 0x7ff9, /* Server Session Begin */
	FC_MS_ZS_SSE	= 0x7ffa, /* Server Session End */
	FC_MS_ZS_CMIT	= 0x7ffb, /* Commit Zone Changes */
	FC_MS_ZS_SPCMIT	= 0x7ffc, /* FC-SP Commit Zone Changes */
};	

#endif /* _FC_MS_H */
