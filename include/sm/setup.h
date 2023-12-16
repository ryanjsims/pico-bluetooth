#pragma once

#include <stdint.h>

namespace sm {
    class setup {
    public:
        setup();

        int process(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);
        bool done();
    private:
        enum class state {
            init,
            simple_pairing,
            filter,
            start_inquiry,
            done
        };

        uint8_t write_simple_pairing_mode();
        uint8_t set_event_filter();

        state m_state;
    };
}