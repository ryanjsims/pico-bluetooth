#pragma once

#include <stdint.h>
#include <bluetooth.h>
#include <string_view>
#include <span>

union device_addr_t {
    bd_addr_t address;
    struct {
        uint8_t b0, b1, b2, b3, b4, b5;
    };
};

class device {
public:
    enum class name {
        not_fetched,
        inquired,
        fetched,
        retry_limit_reached
    };
    enum class connection {
        none,
        available,
        pending,
        established,
        error
    };
    device(std::span<uint8_t> packet);
    ~device();

    device_addr_t address() {
        return m_address;
    }

    uint8_t page_scan_mode() {
        return m_page_scan_mode;
    }

    uint32_t device_class() {
        return m_device_class;
    }

    uint16_t clock_offset() {
        return m_clock_offset;
    }

    int8_t rssi() {
        return m_rssi;
    }

    // Device ID Vendor ID source field
    uint16_t vid_source() {
        return m_vid_source;
    }

    // Device ID Vendor ID field
    uint16_t vid() {
        return m_vid;
    }

    // Device ID Product ID field
    uint16_t pid() {
        return m_pid;
    }

    // Device ID version field
    uint16_t version() {
        return m_version;
    }

    std::string_view get_name() {
        return m_name_sv;
    }

    name name_state() {
        return m_name_state;
    }

    connection connection_state() {
        return m_connection_state;
    }

    // Initiates a GAP remote name request to the device
    void fetch_name();
    /**
     * device::set_name
     * This method takes an HCI event packet and does the following:
     *   1. Checks if it is a GAP inquiry complete event
     *      a. If it is and the name state is inquired, resets the name state 
     *         to not fetched and returns
     *   2. If the event is not a remote name request complete event, returns
     *   3. Checks if the bluetooth address applies to this device, and 
     *      if so, it sets the devices name to the name in the packet.
     */
    bool set_name(uint8_t *remote_name_request_packet);

    hci_con_handle_t get_handle() {
        return m_handle;
    }

    void set_handle(hci_con_handle_t handle) {
        m_handle = handle;
    }

    uint16_t get_control_cid() {
        return m_control_cid;
    }

    void set_control_cid(uint16_t control_cid) {
        m_control_cid = control_cid;
    }

    uint16_t get_interrupt_cid() {
        return m_interrupt_cid;
    }

    void set_interrupt_cid(uint16_t interrupt_cid) {
        m_interrupt_cid = interrupt_cid;
    }

    // True if packet was handled by this device
    bool handle_packet(uint8_t packet_type, uint16_t channel, std::span<uint8_t> packet);

private:
    device_addr_t m_address;
    uint8_t m_page_scan_mode;
    uint32_t m_device_class;
    uint16_t m_clock_offset;
    int8_t m_rssi;
    uint16_t m_vid_source;
    uint16_t m_vid;
    uint16_t m_pid;
    uint16_t m_version;
    hci_con_handle_t m_handle;
    uint16_t m_control_cid;
    uint16_t m_interrupt_cid;
    uint8_t *m_name;
    std::string_view m_name_sv;
    name m_name_state;
    uint8_t m_name_retries;
    connection m_connection_state;

    void construct_from_inquiry_result(std::span<uint8_t> packet);
    void construct_from_connection_request(std::span<uint8_t> packet);

    bool on_hci_event_packet(uint16_t channel, std::span<uint8_t> packet);
    bool on_l2cap_data_packet(uint16_t channel, std::span<uint8_t> packet);
};