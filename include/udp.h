#ifndef VS_UDP_H_
#define VS_UDP_H_

struct UDPHDR {
  u_int16_t	source;
  u_int16_t	dest;
  u_int16_t	len;
  u_int16_t	check;
};

#endif
