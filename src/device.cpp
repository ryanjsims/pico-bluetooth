#include "device.h"
#include "btutils.h"

#include <stdio.h>
#include "logger.h"

#include <pico/stdlib.h>
#include <btstack_event.h>
#include <btstack_hid_parser.h>
#include <gap.h>
#include <l2cap.h>
#include <bluetooth_sdp.h>
#include <classic/sdp_client.h>
#include <functional>

device::device(std::span<uint8_t> packet)
    : m_name_state(device::name::not_fetched)
    , m_connection_state(device::connection::none)
    , m_name(nullptr)
    , m_name_sv{}
    , m_name_retries(3)
    , m_handle(0xFFFF)
    , m_hid_descriptor(nullptr)
    , m_hid_descriptor_len(0)
{
    #if LOG_LEVEL <= LOG_LEVEL_DEBUG
    debug1("Got packet:\n");
    for(int i = 0; i < packet.size(); i++) {
        debug_cont("0x%02x ", packet[i]);
        if(i % 16 == 15) {
            debug_cont1("\n");
        }
        else if(i % 4 == 3) {
            debug_cont1(" ");
        }
    }
    debug_cont1("\n");
    #endif
    uint8_t event = hci_event_packet_get_type(packet.data());
    switch(event) {
    case GAP_EVENT_INQUIRY_RESULT:
        construct_from_inquiry_result(packet);
        break;
    case HCI_EVENT_CONNECTION_REQUEST:
        construct_from_connection_request(packet);
        break;
    default:
        panic("Cannot construct a device from %s\n", bt_strevent(event));
    }

    info("Device found: %s ",   bd_addr_to_str(m_address.address));
    info_cont("with COD: 0x%06x",  device_class());
    if (name_state() == device::name::fetched){
        info_cont(", name '%.*s'", get_name().size(), get_name().data());
    }
    info_cont1("\n");
}

void device::construct_from_inquiry_result(std::span<uint8_t> packet) {
    m_page_scan_mode = gap_event_inquiry_result_get_page_scan_repetition_mode(packet.data());
    m_device_class = gap_event_inquiry_result_get_class_of_device(packet.data());
    m_clock_offset = gap_event_inquiry_result_get_clock_offset(packet.data());
    m_rssi = gap_event_inquiry_result_get_rssi_available(packet.data()) ? gap_event_inquiry_result_get_rssi(packet.data()) : 0;
    gap_event_inquiry_result_get_bd_addr(packet.data(), m_address.address);
    m_connection_state = device::connection::available;
    if(gap_event_inquiry_result_get_device_id_available(packet.data())) {
        m_vid_source = gap_event_inquiry_result_get_device_id_vendor_id_source(packet.data());
        m_vid = gap_event_inquiry_result_get_device_id_vendor_id(packet.data());
        m_pid = gap_event_inquiry_result_get_device_id_product_id(packet.data());
        m_version = gap_event_inquiry_result_get_device_id_version(packet.data());
    }
    if(gap_event_inquiry_result_get_name_available(packet.data())) {
        uint8_t name_len = gap_event_inquiry_result_get_name_len(packet.data());
        m_name = (uint8_t*)malloc(name_len + 1);
        if(m_name == nullptr) {
            panic("device::device: Failed to allocate space for Bluetooth device name!\n");
        }
        memcpy(m_name, gap_event_inquiry_result_get_name(packet.data()), (size_t)name_len);
        m_name[name_len] = 0;
        m_name_sv = {(char*)m_name, name_len};
        m_name_state = device::name::fetched;
    }
}

void device::construct_from_connection_request(std::span<uint8_t> packet) {
    m_page_scan_mode = PAGE_SCAN_MODE_STANDARD;
    m_rssi = 0;
    m_clock_offset = 0xFFFF;
    m_device_class = hci_event_connection_request_get_class_of_device(packet.data());
    hci_event_connection_request_get_bd_addr(packet.data(), m_address.address);
    m_connection_state = device::connection::pending;
}

device::~device() {
    if(m_name != nullptr) {
        free(m_name);
        m_name = nullptr;
    }
}

void device::fetch_name() {
    if(m_name_state != device::name::not_fetched) {
        return;
    }
    info("Fetching name of %s...\n", bd_addr_to_str(m_address.address));
    int rc = gap_remote_name_request(m_address.address, m_page_scan_mode, m_clock_offset | 0x8000);
    if(rc == ERROR_CODE_COMMAND_DISALLOWED) {
        error1("device::fetch_name: Remote name request failed, command disallowed.\n");
        return;
    }
    m_name_state = device::name::inquired;
}

bool device::set_name(uint8_t *packet) {
    if(m_name_state == device::name::fetched || m_name_state == device::name::retry_limit_reached) {
        return false;
    }
    uint8_t event = hci_event_packet_get_type(packet);
    if(event == GAP_EVENT_INQUIRY_COMPLETE && m_name_state == device::name::inquired) {
        m_name_state = device::name::not_fetched;
    }
    if(event != HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE) {
        return false;
    }
    bd_addr_t addr;
    hci_event_remote_name_request_complete_get_bd_addr(packet, addr);
    if(bd_addr_cmp(m_address.address, addr) != 0) {
        return false;
    }
    uint8_t status = hci_event_remote_name_request_complete_get_status(packet);
    if(status != ERROR_CODE_SUCCESS && m_name_retries > 0) {
        error("device::set_name: Remote name request had status %s. %d retries left\n", bt_strerror(status), m_name_retries);
        m_name_retries--;
        return false;
    } else if(status != ERROR_CODE_SUCCESS) {
        m_name_state = device::name::retry_limit_reached;
        return false;
    }
    const char* name = hci_event_remote_name_request_complete_get_remote_name(packet);
    size_t len = strlen(name);
    m_name = (uint8_t*)malloc(len + 1);
    if(m_name == nullptr) {
        panic("device::set_name: Failed to allocate space for Bluetooth device name!\n");
    }
    memcpy(m_name, name, len);
    m_name[len] = 0;
    m_name_sv = {(char*)m_name, len};
    m_name_state = device::name::fetched;
    return true;
}

bool device::handle_packet(uint8_t packet_type, uint16_t channel, std::span<uint8_t> packet) {
    switch(packet_type) {
    case HCI_EVENT_PACKET:
        return on_hci_event_packet(channel, packet);
    case L2CAP_DATA_PACKET:
        return on_l2cap_data_packet(channel, packet);
    default:
        return false;
    }
}

device *queried_device = nullptr;

static void handle_sdp_packet(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    if(queried_device == nullptr) {
        error1("No device to handle SDP query result!\n");
        return;
    }
    queried_device->handle_packet(packet_type, channel, {packet, size});
}

bool device::on_hci_event_packet(uint16_t channel, std::span<uint8_t> packet) {
    uint8_t event = hci_event_packet_get_type(packet.data());
    bd_addr_t addr;
    switch(event) {
    case GAP_EVENT_INQUIRY_COMPLETE:
    case HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE:
        return set_name(packet.data());
    case L2CAP_EVENT_INCOMING_CONNECTION:
        l2cap_event_incoming_connection_get_address(packet.data(), addr);
        if(bd_addr_cmp(m_address.address, addr) != 0) {
            break;
        }
        set_handle(l2cap_event_incoming_connection_get_handle(packet.data()));
        switch(l2cap_event_incoming_connection_get_psm(packet.data())) {
        case PSM_HID_CONTROL:
            set_control_cid(channel);
            break;
        case PSM_HID_INTERRUPT:
            set_interrupt_cid(channel);
            m_connection_state = device::connection::established;
            break;
        }
        l2cap_accept_connection(channel);
        return true;
    case L2CAP_EVENT_CHANNEL_OPENED:{
        if(l2cap_event_channel_opened_get_handle(packet.data()) != m_handle) {
            break;
        }
        uint8_t status = L2CAP_LOCAL_CID_DOES_NOT_EXIST;
        switch(l2cap_event_channel_opened_get_psm(packet.data())) {
        case PSM_HID_CONTROL:
            status = l2cap_request_can_send_now_event(m_control_cid);
            break;
        default:
            break;
        }
        return status == ERROR_CODE_SUCCESS;
    }
    case L2CAP_EVENT_CAN_SEND_NOW:
        if(l2cap_event_can_send_now_get_local_cid(packet.data()) != m_control_cid || queried_device != nullptr) {
            break;
        }
        queried_device = this;
        info("Set queried device as %p\n", this);
        sdp_client_query_uuid16(handle_sdp_packet, (uint8_t *) m_address.address, BLUETOOTH_SERVICE_CLASS_HUMAN_INTERFACE_DEVICE_SERVICE);
        return true;
    case L2CAP_EVENT_CHANNEL_CLOSED:{
        uint8_t channel = l2cap_event_channel_closed_get_local_cid(packet.data());
        if(channel == m_interrupt_cid) {
            set_interrupt_cid(0);
        } else if(channel == m_control_cid) {
            set_control_cid(0);
        } else {
            break;
        }
        return true;
    }
    case HCI_EVENT_DISCONNECTION_COMPLETE:
        if(m_handle != hci_event_disconnection_complete_get_connection_handle(packet.data())) {
            break;
        }
        m_connection_state = device::connection::none;
        m_handle = 0xFFFF;
        return true;
    case SDP_EVENT_QUERY_COMPLETE:
    case SDP_EVENT_QUERY_RFCOMM_SERVICE:
    case SDP_EVENT_QUERY_ATTRIBUTE_BYTE:
    case SDP_EVENT_QUERY_ATTRIBUTE_VALUE:
    case SDP_EVENT_QUERY_SERVICE_RECORD_HANDLE:
        return on_sdp_event_packet(channel, packet);
    }
    return false;
}

void dump_controller(controller_state_t state) {
    printf("Axes: X %5.1f%% Y %5.1f%% Rx %5.1f%% Ry %5.1f%%\tTriggers: L %5.1f%% R %5.1f%%\tHat: %d\tButtons: %03x\r",
        (float)state.left_axes.x / 655.35f,
        (float)state.left_axes.y / 655.35f,
        (float)state.right_axes.x / 655.35f,
        (float)state.right_axes.y / 655.35f,
        (float)state.left_trigger / 10.23f,
        (float)state.right_trigger / 10.23f,
        (uint8_t)state.hat,
        state.buttons
    );
}

bool device::on_l2cap_data_packet(uint16_t channel, std::span<uint8_t> packet) {
    if(channel == m_control_cid) {
        info1("device::on_l2cap_data_packet: Unhandled feature report\n");
        uint16_t i = 0;
        for(i; i < packet.size(); i++) {
            info_cont("0x%02x ", packet[i]);
            if(i % 16 == 15) {
                info_cont1("\n");
            } else if(i % 4 == 3) {
                info_cont1(" ");
            }
        }
        if(i % 16 != 0) {
            info_cont1("\n");
        }
        return true;
    }
    if(channel != m_interrupt_cid) {
        error("Incorrect channel for this device: got 0x%02x, expected 0x%02x\n", channel, m_interrupt_cid);
        return false;
    }
    //btstack_hid_parser_t parser;
    // parse hid stuff here...
    uint8_t report_id = packet[1];
    switch(report_id) {
    case 0x01: // Xbox Controller Joysticks/Triggers/Buttons report
        m_input.left_axes.x = little_endian_read_16(packet.data(), 2);
        m_input.left_axes.y = little_endian_read_16(packet.data(), 4);
        m_input.right_axes.x = little_endian_read_16(packet.data(), 6);
        m_input.right_axes.y = little_endian_read_16(packet.data(), 8);
        m_input.left_trigger = little_endian_read_16(packet.data(), 10);
        m_input.right_trigger = little_endian_read_16(packet.data(), 12);
        m_input.hat = (xbox_hat)packet[14];
        m_input.buttons = little_endian_read_16(packet.data(), 15);
        dump_controller(m_input);
        break;
    case 0x02:
        info("Received Sys Main Menu report: %s\n", packet[2] ? "true" : "false");
        break;
    case 0x03:
        warn1("This is an output report? Shouldn't be received.\n");
        break;
    case 0x04:
        info("Received Battery report: %.1f%%\n", (float)packet[2] / 2.55f);
        break;
    }
    // if(packet.size() > 3) {
    //     uint16_t i = 0;
    //     for(i; i < packet.size(); i++) {
    //         info_cont("0x%02x ", packet[i]);
    //         if(i % 4 == 3) {
    //             info_cont1(" ");
    //         }
    //     }
    //     info_cont1("\r");
    // }
    return true;
}

bool device::on_sdp_event_packet(uint16_t channel, std::span<uint8_t> packet) {
    if(queried_device != this) {
        return false;
    }
    uint8_t event = hci_event_packet_get_type(packet.data());

    switch(event) {
    case SDP_EVENT_QUERY_COMPLETE:{
        queried_device = nullptr;
        debug("Unset queried device %p\n", this);
        if(m_hid_descriptor != nullptr) {
            info1("Received HID descriptor:\n");
            uint16_t i = 0;
            for(i; i < m_hid_descriptor_len; i++) {
                info_cont("0x%02x ", m_hid_descriptor[i]);
                if(i % 16 == 15) {
                    info_cont1("\n");
                } else if(i % 4 == 3) {
                    info_cont1(" ");
                }
            }
            if(i % 16 != 15) {
                info_cont1("\n");
            }
        }
        break;
    }
    case SDP_EVENT_QUERY_RFCOMM_SERVICE:
        break;
    case SDP_EVENT_QUERY_ATTRIBUTE_BYTE:
    case SDP_EVENT_QUERY_ATTRIBUTE_VALUE:
        handle_sdp_attribute(channel, packet);
        break;
    case SDP_EVENT_QUERY_SERVICE_RECORD_HANDLE:
        break;
    default:
        break;
    }
    return true;
}

void device::handle_sdp_attribute(uint16_t channel, std::span<uint8_t> packet) {
    uint16_t length = sdp_event_query_attribute_byte_get_attribute_length(packet.data());
    uint16_t offset = sdp_event_query_attribute_byte_get_data_offset(packet.data());
    uint8_t data = sdp_event_query_attribute_byte_get_data(packet.data());
    uint16_t attribute_id = sdp_event_query_attribute_byte_get_attribute_id(packet.data());
    // info("device::handle_sdp_attribute:\n    attribute %s\n    %d/%d bytes\n    value 0x%02x\n",
    //     bt_strattribute(attribute_id),
    //     offset,
    //     length,
    //     data
    // );
    switch(attribute_id) {
    case BLUETOOTH_ATTRIBUTE_HID_DESCRIPTOR_LIST:
        if(m_hid_descriptor == nullptr) {
            m_hid_descriptor_len = length > 0 ? length : 16;
            m_hid_descriptor = (uint8_t*)malloc(m_hid_descriptor_len);
        }
        if(m_hid_descriptor_len < length) {
            m_hid_descriptor_len = length;
            m_hid_descriptor = (uint8_t*)realloc(m_hid_descriptor, m_hid_descriptor_len);
        }
        if(m_hid_descriptor_len <= offset) {
            error("HID descriptor offset 0x%04x > length 0x%04x\n", offset, m_hid_descriptor_len);
            break;
        }
        if(m_hid_descriptor == nullptr) {
            panic("device::handle_sdp_attribute: Out of memory for hid_descriptor =/\n");
        }
        m_hid_descriptor[offset] = data;
        break;
    }
}