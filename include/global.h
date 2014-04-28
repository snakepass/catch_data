// global.h: 
// Copyright (c) 2013 Vobile Inc. All Rights Reserved.
// wu_shengrui@vobile.cn
// 09/06/2013 04:59:33 PM

#ifndef VS_GLOBAL_H_
#define VS_GLOBAL_H_

#include <map>
#include <vector>
#include <string>
#include <linux/if_packet.h>

char *g_interface = 0;
char *g_back_interface = 0; // 是否需要送回数据包
char *g_bpf = (char*)("");
char *g_conf = 0;       // 配置文件，必须设置
char *g_cpu_profile = 0;
int g_datalink_size = 14;
int g_ip_len = 0;
std::vector<std::map<std::string, std::string> > g_trust_ips;
int g_ffmpeg_timeout;
int g_back_fd;
struct sockaddr_ll g_back_addr;
const char *g_stream_proto_dict[] = {"todetect", "none", "udp", "rtp"};
bool g_debug = false;
int g_enable_ts;
#endif
