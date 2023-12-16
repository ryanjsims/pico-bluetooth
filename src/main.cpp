#include <stdio.h>
#include <btstack.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <pico/multicore.h>

#include <vector>

#include "logger.h"
#include "device.h"
#include "btutils.h"
#include "sm/setup.h"

std::vector<device*> devices;

enum STATE {INIT, ACTIVE};
enum STATE state = INIT;

sm::setup setup_machine;

#define BT_COD_MAJOR_PERIPHERAL 0x0500
#define BT_COD_MAJOR_MASK       0x1F00

#define HID_DATA_INPUT_REPORT ((HID_MESSAGE_TYPE_DATA << 4)|HID_REPORT_TYPE_INPUT)

void log_packet(uint8_t packet_type, uint8_t in, uint8_t *packet, uint16_t len) {
    printf("%s - %s - %s length %d\n", bt_strpacket(packet_type), in ? "in" : "out", bt_strevent(hci_event_packet_get_type(packet)), len);
}

void log_message(int log_level, const char* format, va_list argptr) {
    switch(log_level) {
    case HCI_DUMP_LOG_LEVEL_DEBUG:
        printf("HCI DEBUG - ");
        viprintf(format, argptr);
        break;
    case HCI_DUMP_LOG_LEVEL_INFO:
        printf("HCI INFO - ");
        viprintf(format, argptr);
        break;
    case HCI_DUMP_LOG_LEVEL_ERROR:
        printf("HCI ERROR - ");
        viprintf(format, argptr);
        break;
    default:
        break;
    }
}

void reset() {
    return;
}

hci_dump_t logger = {
    .reset = reset,
    .log_packet = log_packet,
    .log_message = log_message
};

// enum {
//     HCI_OPCODE_HCI_SET_EVENT_FILTER = HCI_OPCODE(OGF_CONTROLLER_BASEBAND, 0x05),
// };

// // 1: Filter type: Connection Setup (0x02)
// // 1: Filter condition type: Allow connection from Class of Devices (0x01)
// // 3: COD
// // 3: COD Mask
// // 1: Autoaccept: 0x011 (no auto-accept), 0x02 (no auto-accept with role disabled)
// //    0x03 (no auto-accept with role enabled)
// const hci_cmd_t hci_set_event_filter_connection_cod = {HCI_OPCODE_HCI_SET_EVENT_FILTER, "11331"};

// // 1: Filter type: Inquiry (0x01)
// // 1: Filter condition type: Allow connection from Class of Devices (0x01)
// // 3: COD
// // 3: COD Mask
// const hci_cmd_t hci_set_event_filter_inquiry_cod = {HCI_OPCODE_HCI_SET_EVENT_FILTER, "1133"};

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);

static btstack_packet_callback_registration_t hci_event_callback_registration;

static bool dump_hci_event = true;
static uint16_t link_handle;
static bool inquiry_for_peer = true;
static bool secure_simple_pairing = true;
static io_capability_t io_capability = IO_CAPABILITY_DISPLAY_ONLY;
static bd_addr_t peer_addr;
static gap_security_level_t security_level = LEVEL_0;

static void start_scan(void){
    info1("Starting inquiry scan..\n");
    gap_inquiry_start(INQUIRY_INTERVAL);
}

static void stop_scan(void){
    info1("Stopping inquiry scan..\n");
    gap_inquiry_stop();
}

// static uint8_t setup_set_event_filter(void) {
//     // Filter out inquiry results before we start the inquiry
//     return hci_send_cmd(&hci_set_event_filter_inquiry_cod, 0x01, 0x01, BT_COD_MAJOR_PERIPHERAL, BT_COD_MAJOR_MASK);
// }

// static uint8_t setup_write_simple_pairing_mode(void) {
//     return hci_send_cmd(&hci_write_simple_pairing_mode, true);
// }

static device* get_device_from_addr(bd_addr_t addr) {
    auto iterator = std::find_if(devices.begin(), devices.end(), [&addr](device *dev){
        return bd_addr_cmp(addr, dev->address().address) == 0;
    });
    if(iterator == devices.end()) {
        return nullptr;
    }
    return *iterator;
}

static bool has_more_remote_name_requests(void){
    return std::any_of(devices.begin(), devices.end(), [](device* dev) {
        return dev->name_state() == device::name::not_fetched;
    });
}

static void do_next_remote_name_request(){
    auto device_to_request = std::find_if(devices.begin(), devices.end(), [](device* dev) {
        return dev->name_state() == device::name::not_fetched;
    });
    if(device_to_request != devices.end()) {
        (*device_to_request)->fetch_name();
    }
}

static void continue_remote_names(void){
    if (has_more_remote_name_requests()){
        do_next_remote_name_request();
        return;
    } 
    start_scan();
}

/* @section Bluetooth Logic 
 *
 * @text The Bluetooth logic is implemented as a state machine within the packet
 * handler. In this example, the following states are passed sequentially:
 * INIT, and ACTIVE.
 */

static void make_acl_link(bd_addr_t remote){
    link_key_t key;
    link_key_type_t key_type;
    if (gap_get_link_key_for_bd_addr(remote, key, &key_type)) {
        info("Link key type %d for %s is found. Drop it\n", key_type, bd_addr_to_str(remote));
        gap_drop_link_key_for_bd_addr(remote);
    }
    
    info("Make a new ACL link to %s\n", bd_addr_to_str(remote));
    gap_connect(remote, BD_ADDR_TYPE_ACL);
    dump_hci_event = true;
}

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
    bd_addr_t addr;
    int i;
    int index;
    
    if (packet_type != HCI_EVENT_PACKET && packet_type != L2CAP_DATA_PACKET) {
        info("Got packet type %s (0x%02x)\n", bt_strpacket(packet_type), packet_type);
        dump_packet(packet, size);
        return;
    }

    uint8_t event = hci_event_packet_get_type(packet);
    uint8_t subevent;
    //printf("Packet size %d - ", size);

    switch(state){
        case INIT:
            setup_machine.process(packet_type, channel, packet, size);
            if(setup_machine.done()) {
                state = ACTIVE;
            }
            break;
        // @text In ACTIVE, the following events are processed:
        //  - GAP Inquiry result event: BTstack provides a unified inquiry result that contain
        //    Class of Device (CoD), page scan mode, clock offset. RSSI and name (from EIR) are optional.
        //  - Inquiry complete event: the remote name is requested for devices without a fetched 
        //    name. The state of a remote name can be one of the following: 
        //    REMOTE_NAME_REQUEST, REMOTE_NAME_INQUIRED, or REMOTE_NAME_FETCHED.
        //  - Remote name request complete event: the remote name is stored in the table and the 
        //    state is updated to REMOTE_NAME_FETCHED. The query of remote names is continued.
        // 
        case ACTIVE:
            switch(event){
                case HCI_EVENT_CONNECTION_REQUEST:
                case GAP_EVENT_INQUIRY_RESULT:{
                    gap_event_inquiry_result_get_bd_addr(packet, addr);

                    device* dev = get_device_from_addr(addr);
                    if (dev != nullptr) break;   // already in our list

                    devices.push_back(new device({packet, size}));
                    if(devices.back()->name_state() == device::name::not_fetched) {
                        devices.back()->fetch_name();
                    }
                    break;
                }
                case GAP_EVENT_PAIRING_COMPLETE:{
                    dump_packet(packet, size);
                    bd_addr_t addr;
                    gap_event_pairing_complete_get_bd_addr(packet, addr);
                    device* dev = get_device_from_addr(addr);
                    if(dev == nullptr) {
                        error1("Device not found for l2cap create channel?\n");
                        return;
                    }
                    uint16_t control_cid;
                    uint8_t status = l2cap_create_channel(packet_handler, addr, BLUETOOTH_PSM_HID_CONTROL, 0xffff, &control_cid);
                    if(status) {
                        error("Connecting or Auth to HID Control failed: 0x%02x\n", status);
                    } else {
                        info1("Set control cid for device.\n");
                        dev->set_control_cid(control_cid);
                    }
                    break;
                }
                case HCI_EVENT_TRANSPORT_PACKET_SENT:
                    if(packet[1] != ERROR_CODE_SUCCESS) {
                        error("Transport packet failed with error %s\n", bt_strerror(packet[1]));
                    }
                    break;
                default:{
                    for(auto dev = devices.begin(); dev != devices.end(); dev++) {
                        if((*dev)->handle_packet(packet_type, channel, {packet, size})) {
                            // When a device handles the packet successfully, stop processing the packet
                            return;
                        }
                    }
                    debug1("No device handled packet:\n");
                    dump_packet(packet, size);
                    break;
                }
            }
            break;
        default:
            break;
    }

    // UNUSED(channel);

    // switch (packet_type) {
    //     case HCI_EVENT_PACKET:
    //         switch (hci_event_packet_get_type(packet)) {
    //             case BTSTACK_EVENT_STATE:
    //                 if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING) return;
    //                 if (inquiry_for_peer) {
    //                     start_scan();
    //                 }
    //                 else {
    //                     make_acl_link(peer_addr);
    //                 }
    //                 break;

    //             case GAP_EVENT_INQUIRY_RESULT:
    //                 gap_event_inquiry_result_get_bd_addr(packet, peer_addr);
    //                 stop_scan();
    //                 if (gap_event_inquiry_result_get_name_available(packet)) {
    //                     char name_buffer[240];
    //                     size_t name_len;
    //                     if (gap_event_inquiry_result_get_name_len(packet) < sizeof(name_buffer)) {
    //                         name_len = gap_event_inquiry_result_get_name_len(packet);
    //                     }
    //                     else {
    //                         name_len = sizeof(name_buffer - 1);
    //                     }
    //                     memcpy(name_buffer, gap_event_inquiry_result_get_name(packet), name_len);
    //                     name_buffer[name_len] = 0;
    //                     printf("Found %s with name %s\n", bd_addr_to_str(peer_addr), name_buffer);
    //                 }
    //                 else {
    //                     printf("Found %s without name, requesting name\n", bd_addr_to_str(peer_addr));
    //                     gap_remote_name_request(peer_addr, gap_event_inquiry_result_get_page_scan_repetition_mode(packet), \
    //                                             gap_event_inquiry_result_get_clock_offset(packet) | 0x8000);
    //                 }
    //                 break;
                    
    //             case HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE:
    //                 if (ERROR_CODE_SUCCESS == hci_event_remote_name_request_complete_get_status(packet)) {
    //                     printf("The name of %s is %s\n", bd_addr_to_str(peer_addr), hci_event_remote_name_request_complete_get_remote_name(packet));
    //                 }
    //                 else {
    //                     printf("Error %s when requesting name of %s\n", bt_strerror(hci_event_remote_name_request_complete_get_status(packet)), bd_addr_to_str(peer_addr));
    //                 }
    //                 make_acl_link(peer_addr);
    //                 break;
    //             case GAP_EVENT_INQUIRY_COMPLETE:
    //                 printf("Inquiry complete status %s\n", bt_strerror(gap_event_inquiry_complete_get_status(packet)));
    //                 break;

    //             case HCI_EVENT_CONNECTION_COMPLETE:
    //                 if (ERROR_CODE_SUCCESS == hci_event_connection_complete_get_status(packet)) {
    //                     link_handle = hci_event_connection_complete_get_connection_handle(packet);
    //                     printf("ACL link 0x%x established.\n", link_handle);
    //                     if (security_level != gap_security_level(link_handle)) {
    //                         printf("Set security level to %d\n", security_level);
    //                         gap_request_security_level(link_handle, security_level);
    //                     }
    //                 }
    //                 else {
    //                     printf("ACL link failed %s\n", bt_strerror(hci_event_connection_complete_get_status(packet)));
    //                 }
    //                 break;

    //             case HCI_EVENT_IO_CAPABILITY_RESPONSE:
    //                 printf("Peer io_capability %d oob_data_present %d authentication_requirements %d\n", \
    //                     hci_event_io_capability_response_get_io_capability(packet), \
    //                     hci_event_io_capability_response_get_oob_data_present(packet), \
    //                     hci_event_io_capability_response_get_authentication_requirements(packet));
    //                 break;

    //             case GAP_EVENT_PAIRING_COMPLETE:
    //                 if (ERROR_CODE_SUCCESS == gap_event_pairing_complete_get_status(packet)) {
    //                     printf("Pairing completed\n");
    //                 }
    //                 else {
    //                     printf("Pairing failed %s\n", bt_strerror(gap_event_pairing_complete_get_status(packet)));
    //                 }
    //                 break;

    //             case GAP_EVENT_SECURITY_LEVEL:
    //                 printf("Link handle 0x%x security level %d\n", \
    //                     gap_event_security_level_get_handle(packet), \
    //                     gap_event_security_level_get_security_level(packet));
    //                 break;

    //             case HCI_EVENT_AUTHENTICATION_COMPLETE:
    //                 printf("Link handle 0x%x authentication status %s\n", \
    //                     hci_event_authentication_complete_get_connection_handle(packet), \
    //                     bt_strerror(hci_event_authentication_complete_get_status(packet)));
    //                 break;

    //             case HCI_EVENT_PIN_CODE_REQUEST:
    //                 // inform about pin code request
    //                 printf("LMP Pairing - pin code request - using '0000'\n");
    //                 hci_event_pin_code_request_get_bd_addr(packet, peer_addr);
    //                 gap_pin_code_response(peer_addr, "0000");
    //                 break;

    //             case HCI_EVENT_USER_CONFIRMATION_REQUEST:
    //                 // inform about user confirmation request
    //                 printf("SSP User Confirmation Request with numeric value '%06"PRIu32"'\n", little_endian_read_32(packet, 8));
    //                 printf("SSP User Confirmation Auto accept\n");
    //                 break;

    //             default:
    //                 if (dump_hci_event) {
    //                     printf("%s\n", bt_strevent(hci_event_packet_get_type(packet)));
    //                 }
    //                 break;
	// 		}
    //         break;

    //     default:
    //         printf("%s\n", bt_strpacket(packet_type));
    //         break;
	// }

}

/* @text For more details on discovering remote devices, please see
 * Section on [GAP](../profiles/#sec:GAPdiscoverRemoteDevices).
 */


void core1_main() {
    multicore_lockout_victim_init();
    return;
}

uint8_t hid_descriptor_storage[512];
uint8_t sdp_service_buffer[100];

int main() {
    stdio_init_all();
    multicore_launch_core1(core1_main);

    // initialize CYW43 driver architecture (will enable BT if/because CYW43_ENABLE_BLUETOOTH == 1)
    if (cyw43_arch_init()) {
        error1("failed to initialise cyw43_arch\n");
        return -1;
    }

    //hci_dump_init(&logger);

    l2cap_init();

    gap_set_security_level(security_level);

    gap_connectable_control(1);

    gap_set_page_scan_type(PAGE_SCAN_MODE_INTERLACED);

    l2cap_register_service(packet_handler, BLUETOOTH_PSM_HID_INTERRUPT, 0xffff, security_level);
    l2cap_register_service(packet_handler, BLUETOOTH_PSM_HID_CONTROL, 0xffff, security_level);

    gap_set_default_link_policy_settings(LM_LINK_POLICY_ENABLE_SNIFF_MODE | LM_LINK_POLICY_ENABLE_ROLE_SWITCH);

    hci_set_inquiry_mode(INQUIRY_MODE_RSSI_AND_EIR);

    hci_set_master_slave_policy(HCI_ROLE_MASTER);

    // register for HCI events
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    gap_ssp_set_enable(secure_simple_pairing);
    if(secure_simple_pairing) {
        gap_ssp_set_io_capability(io_capability);
    }

    // turn on!
    hci_power_control(HCI_POWER_ON);

    hid_protocol_mode_t hid_host_report_mode = HID_PROTOCOL_MODE_REPORT_WITH_FALLBACK_TO_BOOT;
    uint16_t hid_host_cid = 0;

    while(true) {
        auto xbox_controller = std::find_if(devices.begin(), devices.end(), [](device* dev) {
            return dev->get_name().size() > 0 
                && strncmp("Xbox Wireless Controller", dev->get_name().data(), dev->get_name().size()) == 0
                && dev->connection_state() == device::connection::available;
        });
        if(xbox_controller != devices.end() && state == ACTIVE) {
            info1("Found new xbox controller, attempting to bond!\n");
            info("Device %s\nName %.*s\n", bd_addr_to_str((*xbox_controller)->address().address), (*xbox_controller)->get_name().size(), (*xbox_controller)->get_name().data());
            uint8_t status = gap_connect((*xbox_controller)->address().address, BD_ADDR_TYPE_ACL);
            info("Connect status %s\n", bt_strerror(status));
        }
        sleep_ms(1000);
    }
    return 0;
}
