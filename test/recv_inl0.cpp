#include "stdafx.h"
#include "recv_inl.h"
#include "packet.h"
#include "packet.h"
#include "md5.h"
/* 配置数据 */
pcap_t *adhandle = 0;

void recv_inl::test()
{
	// 显示所有设备
	show_all_devices();
	/*std::cout << sizeof(eap_md5_challenge) << std::endl;*/
// 	unsigned char hexData[23] = {
// 		0x04, 
// 		0x30, 0x33, 0x30, 0x30, 0x31, 0x32, 
// 		0x23, 0x3A, 0xBE, 0xB5, 0x9C, 0xEC, 0xC9, 0x8B, 0xC0, 0x9F, 0x6B, 0xC2, 0xEB, 0x76, 0x9B, 0x47
// 	};
// 
// 	MD5 md5(hexData,sizeof(hexData));
// 	std::cout << md5.toString() << std::endl;
}

void recv_inl::show_all_devices()
{
	pcap_if_t *alldev, *d;
	int idevs = 0;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldev, errbuf) == -1){
		std::cerr << "Findalldevs:" << errbuf;
		return;
	}

	for (d = alldev; d; d = d->next){
		if (d->description && d->name){
			std::cout << ++idevs << "." << d->description << std::endl;
			std::cout << " " << d->name << std::endl;
		}
		else
			std::cout << ++idevs << ". No description available. " << std::endl;
	}

	if (idevs == 0){
		std::cerr << "No interfaces found ! Make sure WinPcap is installed.";
	}
}

bool recv_inl::dev_init(int idev,char *code)
{
	pcap_if_t *alldev, *d;
	int idevs = 0;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldev, errbuf) == -1){
		std::cerr << "findalldevs:" << errbuf;
		return false;
	}

	for (d = alldev; d && (idev > 1); d = d->next, idev--){

	}

	if (d == NULL){
		std::cerr << "选择网卡id错误(过大)";
		return false;
	}

	if ((adhandle = pcap_open(d->name,
		65536,
		0,
		1000,
		0,
		errbuf)) == NULL){
		std::cerr << "Unable to open the adapter. " << d->name << " is not supported by WinPcap";

		return false;
	}

	// 网卡配置
	int netmask = 0;
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	//std::cerr << "listening on " << d->name << " ..." ;
	pcap_freealldevs(alldev);

	// 设置过滤
	struct bpf_program fcode;

	if (code == 0 || strlen(code) == 0){
		return true;
	}
	if (pcap_compile(adhandle, &fcode, code, 1, netmask) < 0){
		std::cerr << "error compiling filter: wrong syntax";
		return false;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0){
		std::cerr << "error setting the filter";

		return false;
	}

	return true;
}

/* 处理函数 */
void dispatcher_handler(u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data)
{
	_eth_hdr *hdr = (_eth_hdr *)pkt_data;

	if (hdr->eth_type != 0x8e88){
		return;
	}

	eapol_header *eh = (eapol_header *)(hdr+ 1);
	if (eh->version != 0x01 || eh->type != EAP_TYPE::Packet){
		return;
	}

	extensible_auth *ea = (extensible_auth *)(pkt_data + 14 + 4);
	if (ea->code == 3){	// 成功包
		int offset = 0x1C + pkt_data[0x1B]/*26*/ + 0x69 + 24;
		packet::getInstance()->init_keepalive(hdr->srcmac, 
			*(unsigned int *)&pkt_data[offset]);
		pcap_breakloop(adhandle);
		return;
	}
	if (ea->code != 1){	// 请求包
		return;
	}

	if (ea->type == 1){
		packet::getInstance()->init_indentity(hdr->srcmac , ea->id);
		PKT *indentity = packet::getInstance()->get_identity_pkt();
		recv_inl::send(indentity->data, indentity->len);
	}
	else if (ea->type == 4){
		eap_md5_challenge *emc = (eap_md5_challenge *)ea->identity;
		packet::getInstance()->init_md5_challenge(hdr->srcmac, ea->id,emc->md5,emc->v_size);
		PKT *md5_challenge = packet::getInstance()->get_md5_challenge_pkt();
		recv_inl::send(md5_challenge->data, md5_challenge->len);
	}
}

// 20s发送一个更新包
void recv_inl::install()
{
	bool rc = dev_init(2, "ether proto 0x888e");
	if (rc == 0){
		std::cerr << "初始化失败" << std::endl;
	}

	packet::getInstance()->init_start();
	PKT *start = packet::getInstance()->get_start_pkt();
	send(start->data, start->len);
	//  激活事件
	pcap_loop(adhandle, 0, dispatcher_handler, 0);

	// 保持在线
	while (1){
		packet::getInstance()->keepalive();
		PKT *keepalive = packet::getInstance()->get_keepalive_pkt(); 
		send(keepalive->data, keepalive->len);
		Sleep(20 * 1000);
	}
}

int recv_inl::send(u_char *data, int len)
{
	return pcap_sendpacket(adhandle, data, len);
}