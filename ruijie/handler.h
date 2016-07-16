#pragma once
#include <pcap.h>

class handler
{
public:
	handler();
	~handler();
public:
	void run();
	void send(u_char *data, u_short len);
	void exit();
private:
	int init_dev(const char *dev,const char *code);
private:
	pcap_t *handle;
};

