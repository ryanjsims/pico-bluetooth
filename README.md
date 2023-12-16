## Raspberry Pi Pico W Bluetooth Controller example

This project is a basic example of how to connect to an XBox wireless controller and read the HID reports it emits on the HID interrupt channel using the Raspberry Pi Pico W and btstack.

When the pico first boots, it will start scanning for joystick class input devices (`0x000508`), and if it finds one named 'Xbox Wireless Controller' it will attempt to connect to it.

I used examples from bluepad32 and https://github.com/bluekitchen/btstack/pull/464 to help figure out the flow for pairing to a device and establishing l2cap channels.

General flow when pairing a new device seems to be:
gap_inquiry -> device found -> gap_name_request (if not provided in inquiry response) -> gap_dedicated_bonding -> l2cap_connections

After dedicated bonding, the device will make an hci_connection_request when powered on, using keys exchanged during dedicated bonding to authenticate. Then the l2cap_connections will be established for the HID control and interrupt channels. The HID reports will be sent using the interrupt channel of the device