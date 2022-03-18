import socket
import logging
import json
from typing import Dict, Optional, Type

from pyHS100 import (TPLinkSmartHomeProtocol, TPLinkKLAP, SmartDevice, SmartPlug,
                     SmartBulb, SmartStrip)
from .auth import Auth

_LOGGER = logging.getLogger(__name__)


class Discover:
    DISCOVERY_QUERY = {"system": {"get_sysinfo": None}}

    @staticmethod
    def discover(protocol: TPLinkSmartHomeProtocol = None,
                 port: int = 9999,
                 timeout: int = 3,
                 authentication: Optional[Auth] = None) -> Dict[str, SmartDevice]:
        """
        Sends discovery message to 255.255.255.255:9999 in order
        to detect available supported devices in the local network,
        and waits for given timeout for answers from devices.

        :param protocol: Protocol implementation to use
        :param target: The target broadcast address (e.g. 192.168.xxx.255).
        :param timeout: How long to wait for responses, defaults to 3
        :param port: port to send broadcast messages, defaults to 9999.
        :rtype: dict
        :return: Array of json objects {"ip", "port", "sys_info"}
        """
        if protocol is None:
            protocol = TPLinkSmartHomeProtocol()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)

        req = json.dumps(Discover.DISCOVERY_QUERY)
        _LOGGER.debug("Sending discovery to %s:%s", target, port)

        new_req = bytes.fromhex("020000010000000000000000463cb5d3")
        anonymous = Auth()

        encrypted_req = protocol.encrypt(req)

        sock.sendto(encrypted_req[4:], (target, port))
        sock.sendto(new_req, (target, 20002))

        devices = {}
        _LOGGER.debug("Waiting %s seconds for responses...", timeout)

        try:
            while True:
                data, addr = sock.recvfrom(4096)
                recv_ip, recv_port = addr
                if recv_port == port:
                    info = json.loads(protocol.decrypt(data))
                    device_class = Discover._get_device_class(info)
                    if device_class is not None:
                        devices[recv_ip] = device_class(recv_ip)
                else:
                    info = json.loads(data[16:])
                    device_type = info["result"]["device_type"]
                    if device_type == "IOT.SMARTPLUGSWITCH":
                    	device_class = SmartPlug
                    else:
                    	_LOGGER.error(f"Unknown device type {device_type}")
                    	device_class = None

                    owner = info["result"]["owner"]
                    if owner is not None:
                    	owner_bin = bytes.fromhex(owner)

                    if owner is None or owner == "" or owner_bin == anonymous.owner:
                    	device_auth = anonymous
                    elif authentication is not None and owner_bin == authentication.owner:
                        device_auth = authentication
                    else:
                    	_LOGGER.error(f"Device {recv_ip} has unknown owner {owner}")
                    	device_auth = None

                    if device_class is not None and device_auth is not None:
                        devices[recv_ip] = device_class(recv_ip, protocol=TPLinkKLAP(recv_ip, device_auth))

        except socket.timeout:
            _LOGGER.debug("Got socket timeout, which is okay.")
        except Exception as ex:
            _LOGGER.error("Got exception %s", ex, exc_info=True)
        _LOGGER.debug("Found %s devices: %s", len(devices), devices)
        return devices

    @staticmethod
    def discover_single(
        host: str, protocol: TPLinkSmartHomeProtocol = None
    ) -> Optional[SmartDevice]:
        """Discover a single device by the given IP address.

        :param host: Hostname of device to query
        :param protocol: Protocol implementation to use
        :rtype: SmartDevice
        :return: Object for querying/controlling found device.
        """
        if protocol is None:
            protocol = TPLinkSmartHomeProtocol()

        info = protocol.query(host, Discover.DISCOVERY_QUERY)

        device_class = Discover._get_device_class(info)
        if device_class is not None:
            return device_class(host)

        return None

    @staticmethod
    def _get_device_class(info: dict) -> Optional[Type[SmartDevice]]:
        """Find SmartDevice subclass for device described by passed data."""
        if "system" in info and "get_sysinfo" in info["system"]:
            sysinfo = info["system"]["get_sysinfo"]
            if "type" in sysinfo:
                type_ = sysinfo["type"]
            elif "mic_type" in sysinfo:
                type_ = sysinfo["mic_type"]
            else:
                raise SmartDeviceException("Unable to find the device type field!")
        else:
            raise SmartDeviceException("No 'system' nor 'get_sysinfo' in response")

        if "smartplug" in type_.lower() and "children" in sysinfo:
            return SmartStrip
        elif "smartplug" in type_.lower():
            return SmartPlug
        elif "smartbulb" in type_.lower():
            return SmartBulb

        return None
