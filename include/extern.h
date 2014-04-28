// extern.h: 
// 09/06/2013 05:28:56 PM

#ifndef VS_EXTERN_H_
#define VS_EXTERN_H_

#include <map>
#include <vector>
#include <string>

extern char *g_interface;
extern char *g_back_interface;
extern char *g_bpf;
extern char *g_conf;
extern char *g_cpu_profile;
extern int g_datalink_size;
extern int g_ip_len;
extern std::vector<std::map<std::string, std::string> > g_trust_ips;
extern int g_ffmpeg_timeout;
extern int g_back_fd;
extern struct sockaddr_ll g_back_addr;
extern const char *g_stream_proto_dict[];
extern bool g_debug;
extern int g_enable_ts;
#endif
