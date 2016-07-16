#pragma once
#include <sys/types.h>

/* 结构定义 */
struct _eth_hdr	/* 网路层 */
{
	u_char dstmac[6]; //
	u_char srcmac[6]; //
	u_short eth_type; //
}__attribute__((packed));

struct eapol_header {
	u_char version;
	u_char type;
	u_short length;
}__attribute__((packed));

struct extensible_auth{
	u_char code;
	u_char id;
	u_short length;
	u_char type;
	u_char identity[0];
}__attribute__((packed));

struct eap_md5_challenge{
	u_char v_size;
	u_char md5[0x10];
	u_char extra_data[0];
}__attribute__((packed));

enum EAP_TYPE
{
	Packet = 0,
	Start = 1,
	Logoff = 2,
	Keepalive = 191
};

// 自定义结构
struct PKT
{
	u_char *data;
	u_short len;
}__attribute__((packed));

class packet
{
public:
	packet();
	~packet();
public:
	static packet *getInstance();
private:
	PKT start_pkt;
	PKT indentity_pkt;
	PKT md5challenge_pkt;
	PKT keepalive_pkt;
public:
	void init(const char *dev);
	void init_start();
	void init_indentity(u_char *dst_mac, u_char id);
	void init_md5_challenge(u_char*dst_mac, u_char id, u_char *md5, u_short len);
	void init_keepalive(u_char*dst_mac, unsigned int key);
	void keepalive();
private:
	void init_eth(_eth_hdr *hdr, u_char *src_mac, u_char *dst_msc);
	void init_eapol(eapol_header*, u_char type, u_short length, u_char version = 1 /*802.1X-2001*/);
	void init_extra_data(u_char *);
	u_short exAp(u_char *, u_char code, u_char id, u_char type, u_char *identity, u_short length);
public:
	PKT *get_start_pkt(){
		return &start_pkt;
	}
	PKT *get_identity_pkt(){
		return &indentity_pkt;
	}
	PKT *get_md5_challenge_pkt(){
		return &md5challenge_pkt;
	}
	PKT *get_keepalive_pkt(){
		return &keepalive_pkt;
	}
private:
	unsigned int number;
	unsigned int ka_key;
};

