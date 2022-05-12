import socket
import struct
import textwrap
from socket import *
import socket as Socket
#from gevent.socket import socket
#import gevent
TAB_1 = '\t - '
TAB_2 = '\t\t - '

DATA_TAB_2 = '\t\t '
BUFFER_SIZE = 65536


# Unpack ethernet frame
def ethernetFrame(data):
    destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
    return getMacAddr(destMac), getMacAddr(srcMac), socket.htons(proto), data[14:]


# MAC address (AA:BB:CC:DD:EE:FF)
def getMacAddr(bytesAddr):
    bytesStr = map('{:02x}'.format, bytesAddr)
    macAddr = ':'.join(bytesStr).upper()
    return macAddr


# IPv4 packet
def ipv4Packet(data):
    versionHeaderLen = data[0]
    version = versionHeaderLen >> 4
    headerLen = (versionHeaderLen & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLen, ttl, proto, ipv4(src), ipv4(target), data[headerLen:]


def ipv4(addr):
    return '.'.join(map(str, addr))


# ICMP packet
def icmpPacket(data):
    icmpType, code, checksum = struct.unpack('! B B H', data[:4])
    return icmpType, code, checksum, data[4:]


# TCP segment
def tcpSegment(data):
    (srcPort, destPort, sequence, acknowledgement,
     offsetReversedFlags) = struct.unpack('! H H L L H', data[:14])
    offset = (offsetReversedFlags >> 12) * 4
    flagUrg = (offsetReversedFlags & 32) >> 5
    flagAck = (offsetReversedFlags & 16) >> 4
    flagPsh = (offsetReversedFlags & 8) >> 3
    flagRst = (offsetReversedFlags & 4) >> 2
    flagSyn = (offsetReversedFlags & 2) >> 1
    flagFin = (offsetReversedFlags & 1)
    return srcPort, destPort, sequence, acknowledgement, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data[offset:]


# Format data
def formatMultiLine(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if (size % 2):
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def main():
    # INET raw socket
    
    socket.Socket(socket.AF_INET6, socket.SOCK_RAW, socket.ntohs(3))
    print("socket is created")

    while (True):
        rawData, addr = Socket.recvfrom(BUFFER_SIZE)
        destMac, srcMac, ethProto, data = ethernetFrame(rawData)
        print(
            f'Source : {srcMac}, Destination: {destMac}, Protocol: {ethProto}')

        # IPv4
        if (ethProto == 8):
            (version, headerLen, ttl, proto,
             src, target, data) = ipv4Packet(data)
            print('IPv4 Packet:')
            print(
                f'{TAB_1} Version: {version}, Header Length: {headerLen}, TTL: {ttl}')
            print(f'{TAB_1} Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if (proto == 1):
                icmpType, code, checksum, data = icmpPacket(data)
                print('ICMP Packet: ')
                print(
                    f'{TAB_1} Type: {icmpType}, Code: {code}, Checksum: {checksum},')
                print(f'{TAB_1} Data: ')
                print(formatMultiLine(DATA_TAB_2, data))

            # TCP
            elif (proto == 6):
                (srcPort, destPort, sequence, acknowledgement, flagUrg, flagAck,
                 flagPsh, flagRst, flagSyn, flagFin, data) = tcpSegment(data)
                print('TCP Packet: ')
                print(f'{TAB_1} Src: {srcPort}, Dest: {destPort}')
                print(f'{TAB_1} Seq: {sequence}, Ack: {acknowledgement}')
                print(f'{TAB_1} Flags')
                print(f'{TAB_2} URG: {flagUrg}, ACK: {flagAck}, PSH: {flagPsh}')
                print(f'{TAB_2} RST: {flagRst}, SYN: {flagSyn}, FIN:{flagFin}')
                print(f'{TAB_1} Data: ')
                print(formatMultiLine(TAB_2, data))
        print()


main()