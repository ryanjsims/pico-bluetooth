#pragma once

#include <stdint.h>

void dump_packet(uint8_t* packet, uint16_t size);
const char* bt_strerror(uint8_t error_code);
const char* bt_strhcistate(uint8_t state);
const char* bt_strpacket(uint8_t packet_type);
const char* bt_strevent(uint8_t event);
const char* bt_strlinktype(uint8_t link_type);
const char* bt_stropcode(uint16_t opcode);
const char* bt_strhidsubevent(uint8_t subevent);
const char* bt_striocap(uint8_t io_capability);
const char* bt_strauthreq(uint8_t auth_reqs);
const char* bt_strpsm(uint16_t psm);