#!/usr/bin/env python

import argparse
import configparser
import fcntl
import os
import struct
from socket import socket
from typing import Iterator

import bluetooth
import bluetooth._bluetooth as bluez
from crccheck.crc import Crc24Ble


VSC_GetHidDeviceList = 0x36
VSC_AddHIDDevice = 0x37
VSC_RemoveHIDDevice = 0x39
VSC_EnableUSBHIDEmulation = 0x3B


def hci_devba(hci_id: int, sock: socket) -> bytes:
    # The size of the hci_dev_info struct is not fully defined.
    # It's 89 with no padding, and observed to be 92 on one system, so rounding
    # up.
    req = bytearray(128)
    struct.pack_into('H', req, 0, hci_id)
    fcntl.ioctl(sock, bluez.HCIGETDEVINFO, req)
    response = struct.unpack_from('H8s6sIb8b3I4H10I', req)
    return response[2]


def list_hid_devices(hci_id: int):
    sock: socket = bluez.hci_open_dev(hci_id)
    try:
        response: bytearray = bluez.hci_send_req(sock, bluez.OGF_VENDOR_CMD,
                                                 VSC_GetHidDeviceList,
                                                 bluez.EVT_CMD_COMPLETE, 256, b'')

        count: int = struct.unpack_from('!H', response)[0]
        # Note that the actual entry is:
        # 6 Bytes: Device Address
        # 3 Bytes: Some sort of 24bit Checksum
        # 1 Byte: Padding
        #
        # But it's way easier to extract the checksum by abusing the presence
        # of the padding byte to read a 32bit integer
        num_entries = 0
        entries: Iterator[tuple[bytes, int]] = struct.iter_unpack('<6sI', response[2:])
        for entry in entries:
            addr: str = bluez.ba2str(entry[0])
            num_entries += 1
            print('%s: 0x%06X' % (addr, entry[1]))

        if count != num_entries:
            print('Warning: Expected %d entries but saw %d.' % (count, num_entries))

    finally:
        sock.close()


def add_hid_device(hci_id: int, address: str, link_key: str):
    sock: socket = bluez.hci_open_dev(hci_id)
    try:
        baddr: bytes = bluez.str2ba(address)
        bkey = bytes.fromhex(link_key)
        crc = Crc24Ble.calc(bkey).to_bytes(3, 'little')
        req = baddr + bkey + crc

        bluez.hci_send_req(sock, bluez.OGF_VENDOR_CMD, VSC_AddHIDDevice,
                           bluez.EVT_CMD_COMPLETE, 0, req)
    finally:
        sock.close()


def remove_hid_device(hci_id: int, address: str):
    sock: socket = bluez.hci_open_dev(hci_id)
    try:
        baddr: bytes = bluez.str2ba(address)

        bluez.hci_send_req(sock, bluez.OGF_VENDOR_CMD, VSC_RemoveHIDDevice,
                           bluez.EVT_CMD_COMPLETE, 0, baddr)
    finally:
        sock.close()


def set_hid_proxy_mode(hci_id: int, mode: bool):
    sock: socket = bluez.hci_open_dev(hci_id)
    try:
        bmode: bytes = mode.to_bytes()

        bluez.hci_send_req(sock, bluez.OGF_VENDOR_CMD, VSC_EnableUSBHIDEmulation,
                           bluez.EVT_CMD_COMPLETE, 0, bmode)
    finally:
        sock.close()


def get_system_link_key(hci_id: int, hid_addr: str) -> str:
    sock: socket = bluez.hci_open_dev(hci_id)
    try:
        baddr = hci_devba(hci_id, sock)
        hci_addr = bluez.ba2str(baddr)
        info_path = os.path.join('/var/lib/bluetooth', hci_addr, hid_addr, 'info')
        if os.path.exists(info_path):
            config = configparser.ConfigParser()
            config.read(info_path)
            link_key = config['LinkKey']['Key']
            if link_key is None:
                raise KeyError('"%s" does not contain a link key' % info_path)
            return link_key
        else:
            raise FileNotFoundError('"%s" does not exist' % info_path)
    finally:
        sock.close()


def do_list(args: argparse.Namespace):
    list_hid_devices(args.device)


def do_add(args: argparse.Namespace):
    link_key: str = args.link_key
    if (args.system_settings):
        link_key = get_system_link_key(args.device, args.address)
    add_hid_device(args.device, args.address, link_key)


def do_remove(args: argparse.Namespace):
    remove_hid_device(args.device, args.address)


def do_set_proxy_mode(args: argparse.Namespace):
    mode = args.active == 'on'
    set_hid_proxy_mode(args.device, mode)


def validate_dev_id(input: str) -> int:
    if input.isdigit():
        input = 'hci%s' % (input)
    ret = bluez.hci_devid(input)
    if ret >= 0:
        return ret
    else:
        raise ValueError()


def validated_address(input: str) -> str:
    if bluetooth.is_valid_address(input):
        return input
    else:
        raise ValueError()


def validated_link_key(input: str) -> str:
    if len(input) == 32 and int(input, 16):
        return input
    else:
        raise ValueError()


def main():
    parser = argparse.ArgumentParser(prog='bcm-hid-proxy',
                                     description='''
        A utility to configure the HID Proxy mode of Broadcom Bluetooth adapters''')
    parser.add_argument('--device', '-i', type=validate_dev_id, default='hci0',
                        help='HCI device')

    commandparsers = parser.add_subparsers(help='Commands', required=True)
    list_parser = commandparsers.add_parser('list', help='List stored HID devices')
    list_parser.set_defaults(func=do_list)

    add_parser = commandparsers.add_parser('add', help='Add a HD device')
    add_parser.set_defaults(func=do_add)
    add_parser.add_argument('--address', '-a', help='Address of HID device',
                            required=True, type=validated_address)
    group = add_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--link-key', '-l', help='Link Key', type=validated_link_key)
    group.add_argument('--system-settings', '-s', action='store_const', const=True,
                       help='Read Link Key from System Settings')

    remove_parser = commandparsers.add_parser('remove', help='Remove a HD device')
    remove_parser.set_defaults(func=do_remove)
    remove_parser.add_argument('--address', '-a', help='Address of HID device',
                               required=True, type=validated_address)

    set_mode_parser = commandparsers.add_parser('set-mode', help='Set the HID Proxy mode')
    set_mode_parser.add_argument('active', choices=['on', 'off'],
                                 help='Turn proxy mode on or off')
    set_mode_parser.set_defaults(func=do_set_proxy_mode)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
