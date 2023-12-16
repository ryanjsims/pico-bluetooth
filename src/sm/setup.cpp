#include "sm/setup.h"
#include "btutils.h"

#include <btstack.h>
#include <stdio.h>
#include "logger.h"

#define BT_COD_MAJOR_PERIPHERAL 0x0500
#define BT_COD_MAJOR_MASK       0x1F00

enum {
    HCI_OPCODE_HCI_SET_EVENT_FILTER = HCI_OPCODE(OGF_CONTROLLER_BASEBAND, 0x05),
};

// 1: Filter type: Connection Setup (0x02)
// 1: Filter condition type: Allow connection from Class of Devices (0x01)
// 3: COD
// 3: COD Mask
// 1: Autoaccept: 0x01 (no auto-accept), 0x02 (no auto-accept with role disabled)
//    0x03 (no auto-accept with role enabled)
const hci_cmd_t hci_set_event_filter_connection_cod = {HCI_OPCODE_HCI_SET_EVENT_FILTER, "11331"};

// 1: Filter type: Inquiry (0x01)
// 1: Filter condition type: Allow connection from Class of Devices (0x01)
// 3: COD
// 3: COD Mask
const hci_cmd_t hci_set_event_filter_inquiry_cod = {HCI_OPCODE_HCI_SET_EVENT_FILTER, "1133"};

using namespace sm;

setup::setup()
    : m_state(setup::state::init)
{}

bool setup::done() {
    return m_state == setup::state::done;
}

int setup::process(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    debug1("setup::process -----\n");
    #if LOG_LEVEL <= LOG_LEVEL_DEBUG
    dump_packet(packet, size);
    #endif

    uint8_t status, event = hci_event_packet_get_type(packet);

    switch(m_state) {
    case setup::state::init:
        if(event != BTSTACK_EVENT_STATE || btstack_event_state_get_state(packet) != HCI_STATE_WORKING) {
            debug1("btstack state != HCI_STATE_WORKING\n");
            break;
        }
        m_state = setup::state::simple_pairing;
        // intentionally fall through
    case setup::state::simple_pairing:
        status = write_simple_pairing_mode();
        debug("setup::process: Writing simple pairing mode: %s\n", bt_strerror(status));
        if(status) {
            error("setup::process: Failed to write simple pairing mode: %s\n", bt_strerror(status));
            break;
        }
        info1("Set simple pairing mode\n");
        m_state = setup::state::filter;
        break;
    case setup::state::filter:
        status = set_event_filter();
        if(status) {
            error("setup::process: Failed to set event filter: %s\n", bt_strerror(status));
            break;
        }
        info1("Set event filter.\n");
        m_state = setup::state::start_inquiry;
        break;
    case setup::state::start_inquiry:
        status = gap_inquiry_start(INQUIRY_INTERVAL);
        if(status) {
            error("setup::process: Failed to start gap inquiry: %s\n", bt_strerror(status));
            break;
        }
        info1("Starting gap inquiry...\n");
        m_state = setup::state::done;
        break;
    case setup::state::done:
        break;
    }

    debug1("end setup::process -----\n");
    return (int)m_state;
}

uint8_t setup::write_simple_pairing_mode() {
    if(!hci_can_send_command_packet_now()) {
        warn1("Cannot send HCI command at the moment, trying later...\n");
        return ERROR_CODE_COMMAND_DISALLOWED;
    }
    return hci_send_cmd(&hci_write_simple_pairing_mode, true);
}

uint8_t setup::set_event_filter() {
    if(!hci_can_send_command_packet_now()) {
        warn1("Cannot send HCI command at the moment, trying later...\n");
        return ERROR_CODE_COMMAND_DISALLOWED;
    }
    return hci_send_cmd(&hci_set_event_filter_inquiry_cod, 0x01, 0x01, BT_COD_MAJOR_PERIPHERAL, BT_COD_MAJOR_MASK);
}