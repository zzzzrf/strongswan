#ifndef __IKE_VTY_H__
#define __IKE_VTY_H__

struct isakmp_policy {
	int set;
	int priority;
	int lifetime;
	char encryption[16];
	char hash[16];
	char group[16];
	int auth_method;/*POLICY_PSK;POLICY_RSASIG*/
};

struct isakmp_gateway {
	int set; /*set or no set */
	int version;	/* 0 -> ikev1/ikev2		1 -> ikev1		2->ikev2 */
	int bindtotunnel;/**/
	int isaddr;
	char name[MAX_NAME];
	/* �Զ�����IP��ַ */
	struct ipaddr other;
	/* ��������IP��ַ */
	struct ipaddr me;
	char domain[128];
	int ipsec_type;/*0:Site-to-Site  1:PC-to-Site*/
	int isakmp_mode;/*0:main mode;1:aggressive mode*/
	int dpd_enable;
	int dpd_interval;
	int dpd_retry_times;
	int dpd_timeout;
	int nat_keepalive;
	int lifetime;
	char group[16];
	int auth_method;/*POLICY_PSK;POLICY_RSASIG*/
	char pre_key[MAX_SECRET];
	char local_cert[MAX_SECRET];
	int if_id_in;
	int if_id_out;


#ifdef CONFIG_XAUTH
	int xauth_mode ;  // 0  disable  1; server ;2 client
	char usergroup[64];
	int mode_cfg ;     //0  disable 1 :server ;2 client
	u_int32_t start_ip;
	u_int32_t end_ip;		
	u_int32_t dns;
	u_int32_t wins;	
	struct ifconfig_pool pool;
#endif
	list   policylist;/*-->struct isakmp_policy*/
	struct thread *timer_th;
	int dns_fd;
	struct thread * dns_read_th;

	int enable;
	int fw_id;
	int acl_group_number; 
	char remote_subnet[256];
	char local_subnet[256];
	struct sev_obj_trans service;
	char interface[MAX_NAME+1];
	char ike_id_type[16];
	char remote_gw_id[MAX_SHORT_NAME+1];
	char local_gw_id[MAX_SHORT_NAME+1];

	int src_net_type;
	int dst_net_type;

	int recon_enable;
	int del_redundant_sa;

	char VrfName[VRF_NAME_LEN + 1];
	int  VtiId;
	char sm2_sig_cert[32];
	char sm2_enc_cert[32];
	sctl_keep_alive_t *keep_alive;
};

struct vtysh_isakmp_gateway {
#ifdef CONFIG_RCIOS_CWMP 	
	int instance;
#endif
	int version;	/* 0 -> ikev1/ikev2		1 -> ikev1		2->ikev2 */
	int bindtotunnel;/**/
	char name[MAX_NAME];
	char remote_addr[IPADDR_STRING_SIZE];
	char local_addr[IPADDR_STRING_SIZE];
	char domain[128];
	int ipsec_type;/*0:Site-to-Site  1:PC-to-Site*/
	int isakmp_mode;/*0:main mode;1:aggressive mode*/
	int dpd_enable;
	int dpd_interval;
	int dpd_timeout;
	int nat_keepalive;
	int lifetime;
	char group[16];
	int auth_method;/*POLICY_PSK;POLICY_RSASIG*/
	char pre_key[MAX_SECRET];
	char local_cert[MAX_SECRET];
	int if_id_in;
	int if_id_out;

#ifdef CONFIG_XAUTH
	int xauth_mode ;  // 0  disable  1; server ;2 client
	char usergroup[64];
	int mode_cfg ;     //0  disable 1 :server ;2 client
	u_int32_t start_ip;
	u_int32_t end_ip;		
	u_int32_t dns;
	u_int32_t wins;	
#endif

	struct isakmp_policy policy[3];
	int enable;
	int fw_id;
	int acl_group_number;
	char remote_subnet[IPSEC_SUBNET_LEN];
	char local_subnet[IPSEC_SUBNET_LEN];
	char service_name[32];
	char interface[MAX_NAME+1];
	char ike_id_type[16]; //ip or domain
	char remote_gw_id[MAX_SHORT_NAME+1];
	char local_gw_id[MAX_SHORT_NAME+1];
	int src_net_type;
	int dst_net_type;

	int recon_enable;
	int del_redundant_sa;
	char VrfName[VRF_NAME_LEN + 1];
	int  VtiId;
	char sm2_sig_cert[32];
	char sm2_enc_cert[32];
	int keep_alive_timeout;
};

struct mode_st
{
    int mode;//main or aggressive mode
};

struct psk {
	int remove;
	char key[MAX_SECRET];
};

struct map {
	int refcnt;
	char map_name[MAX_NAME];
	char gateway[MAX_NAME];
	struct map *oldmap;
    list tranformlist;
	char ike[128];		
	char esp[128];
	int local_set;
	char left[16];
	char right[16];
	char leftsubnet[32];
	char rightsubnet[32];
	int compress;
	int keylife_sec;
	unsigned long keylife_kby;
	int ikelift;
	int mode;
	int pfs;
	int level; /* 0 is per map, 1 is per host */
	int sa_type;
	char pfsgroup[16];
	int seq;
	char identity_fqdn[128]; 	/* Save peer id */
	char *myid;			/* Save my id */
	int ifref;
	char auth_by;			/* Point authentication method , 
	 				   Currently 0 is by psk, 1 is by rsa-sig */
	/* for manual map only*/	
	int auth_key_len,enc_key_len;
	unsigned int spi_ah_in, spi_ah_out,spi_esp_in,spi_esp_out,replaywin;
	char *ah_authkey_in, *esp_authkey_in, *esp_encrkey_in;
	char *ah_authkey_out, *esp_authkey_out, *esp_encrkey_out;
	char ah_auth[16];	 /* hmac-md5-96 | hmac-sha1-96 */
	int netlen;
	int enable;
	int VtiId;
	int mark_in;
	int mark_out;
};

struct vtysh_tunnel
{
        int set;
	union {
	     char name[MAX_NAME];
             int mode;
	     int pfs;
	     struct {
	     int second;
	     int kby;
	     int keylife_sec;
	     unsigned long keylife_kby;
	     }st2;
	     int netlen;
	     struct {
			int mark_in;
			int mark_out;
	     } vti_mark;
	}u;
};

struct transform {
	int priority;
	char alg_sets[2][32];	/* set ESP && AH */
	int ah;			/* If 1 use AH */
	int esp;	          /* If 1 use ESP */
	char ah_xform[16];	 /* hmac-md5-96 | hmac-sha1-96 */
	char pfsgroup[16];
};

struct vtysh_transform {
    int set;
	int priority;
	int mode;		
	char alg_sets[2][32];
	char ah_xform[16];
	int pfs;
	int ah;
	int esp;
};

struct vtysh_show_tunnel {
     char name[MAX_NAME];
     int refcnt;
     char gw_name[MAX_NAME];
     int mode;
     int pfs;
     int keylife_sec;
     unsigned long keylife_kby;
	 struct transform ts[3];

	// added by liangxia, 2011.11.16
     int netlen;
	// end
	int mark_in;
	int mark_out;
};

struct vty_ike_event
{
	int  count;
	char event[32];
	char ike[MAX_SHORT_NAME];
	char child[MAX_SHORT_NAME];
};

sctl_keep_alive_t *sctl_keep_alive_create(struct isakmp_gateway *gateway, int timeout);

#endif
