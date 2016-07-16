#include "handler.h"
#include <string.h>
#include <iostream>
#include "packet.h"
#include <unistd.h>

handler::handler()
{
}

handler::~handler()
{
}

/* 处理函数 */
void dispatcher_handler(u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data)
{
	handler *h = (handler *)param;
	_eth_hdr *hdr = (_eth_hdr *)pkt_data;

	if (hdr->eth_type != 0x8e88){
		return;
	}

	eapol_header *eh = (eapol_header *)(hdr + 1);
	if (eh->version != 0x01 || eh->type != EAP_TYPE::Packet){
		return;
	}

	extensible_auth *ea = (extensible_auth *)(pkt_data + 14 + 4);
	if (ea->code == 3){	// 成功包
		printf("[+]ALL DONE.\n");
		int offset = 0x1C + pkt_data[0x1B]/*26*/ + 0x69 + 24;
		packet::getInstance()->init_keepalive(hdr->srcmac,
			*(unsigned int *)&pkt_data[offset]);
		h->exit();
		return;
	}
	if (ea->code != 1){	// 请求包
		return;
	}

	if (ea->type == 1){
		printf("[+]NEED IDENTITY.\n");
		packet::getInstance()->init_indentity(hdr->srcmac, ea->id);
		PKT *indentity = packet::getInstance()->get_identity_pkt();
		h->send(indentity->data, indentity->len);
		printf("[i]SEND IDENTITY.\n");
	}
	else if (ea->type == 4){
		printf("[+]NEED PASSWORD.\n");
		eap_md5_challenge *emc = (eap_md5_challenge *)ea->identity;
		packet::getInstance()->init_md5_challenge(hdr->srcmac, ea->id, emc->md5, emc->v_size);
		PKT *md5_challenge = packet::getInstance()->get_md5_challenge_pkt();
		h->send(md5_challenge->data, md5_challenge->len);
		printf("[i]SEND PASSWORD.\n");
	}
}

void handler::run()
{
	// 初始化
	int rc = init_dev("eth0", "ether proto 0x888e");
	if (rc < 0)	return;

	packet::getInstance()->init_start();
	PKT *start = packet::getInstance()->get_start_pkt();
	pcap_sendpacket(handle, start->data, start->len);
	
	printf("[i]SEARCH SERVER.\n");

	pcap_loop(handle, 0, dispatcher_handler, (u_char *)this);

	printf("[i]ENTER KEEPALIVE.\n");
	// 保持在线
	while (1){
		packet::getInstance()->keepalive();
		PKT *keepalive = packet::getInstance()->get_keepalive_pkt();
		pcap_sendpacket(handle, keepalive->data, keepalive->len);
		sleep(20);
	}
}

int handler::init_dev(const char *dev,const char *code)
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	if (dev == 0 || strlen(dev) == 0){
		dev = pcap_lookupdev(errbuf);
	}

	handle = pcap_open_live(dev, BUFSIZ,  false, 0, errbuf);
	if (handle == 0){
		std::cout << "open dev error:" << std::endl;
		std::cout << errbuf << std::endl;
		return -1;
	}
	// 设置过滤条件
// 	bpf_u_int32 mask;
// 	bpf_u_int32 net;
// 	int rc = pcap_lookupnet(dev, &net, &mask, errbuf);
// 	if (rc == -1){
// 		std::cout << "pcap lookup error:" << std::endl;
// 		std::cout << errbuf << std::endl;
// 		return -1;
// 	}
	struct bpf_program fcode;
	pcap_compile(handle, &fcode, code, 1,0 /*mask*/);
	pcap_setfilter(handle, &fcode);

	packet::getInstance()->init(dev);

	return 0;
}

void handler::send(u_char *data, u_short len)
{
	pcap_sendpacket(handle, data, len);
}

void handler::exit()
{
	pcap_breakloop(handle);
}