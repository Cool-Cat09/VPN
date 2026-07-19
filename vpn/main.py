from cdef import kernel, iphlp, wintun, ffi
import logging
import ipaddress
import socket
import asyncio


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
console_log = logging.StreamHandler()
formatter = formatter = logging.Formatter("%(asctime)s - [%(name)s] - %(levelname)s - %(message)s")
console_log.setFormatter(formatter)
log.addHandler(console_log)


def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        total += word
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
        
    return (~total) & 0xffff

class WintunTunnel():
    def __init__(
            self, 
            ip_address: str,
            prefix_lenght: int,
            server_ip: str,
            server_port: int,
            adapter_name: str = 'ValetVPN',
            pool_name: str = 'ValetPool',
            ):
        self.adapter_name = ffi.new('wchar_t[]', adapter_name)
        self.pool_name = ffi.new('wchar_t[]', pool_name)
        self.ip_address = ipaddress.IPv4Address(ip_address)
        self.prefix_length = prefix_lenght
        self.server_address = (server_ip, server_port)
        self.adapter = None
        self.session = None
        self.read_event = None
    
    def up(self):
        row = ffi.new('MIB_UNICASTIPADDRESS_ROW *')
        luid = ffi.new('NET_LUID *')

        self.adapter = wintun.WintunCreateAdapter(self.adapter_name, self.pool_name, ffi.NULL)

        iphlp.InitializeUnicastIpAddressEntry(row)

        wintun.WintunGetAdapterLUID(self.adapter, luid)
        log.info(luid.Value)
        self.session = wintun.WintunStartSession(self.adapter, 0x4000000)
        self.read_event = wintun.WintunGetReadWaitEvent(self.session)

        row.InterfaceLuid.Value = luid.Value
        row.Address.Ipv4.sin_family = 2
        row.Address.Ipv4.sin_addr.S_un.S_addr = socket.htonl(int(self.ip_address))
        row.OnLinkPrefixLength = self.prefix_length
        row.SkipAsSource = 0
        row.ValidLifetime = 0xffffffff
        row.PreferredLifetime = 0xffffffff
        
        result = iphlp.CreateUnicastIpAddressEntry(row)
        log.info(f"Код ответа Windows API (Create IP): {result}")
    
    def run_loop(self):
        while 1:
            if kernel.WaitForSingleObject(self.read_event, 100) == 0:
                while 1:
                    packet_size = ffi.new('DWORD *')
                    packet_addr = wintun.WintunReceivePacket(self.session, packet_size)
                    if packet_addr == ffi.NULL or packet_addr is None:
                        break
                    packet_bytes = bytearray(ffi.buffer(packet_addr, packet_size[0]))
                    wintun.WintunReleaseReceivePacket(self.session, packet_addr)
                    if packet_bytes[9] != 1:
                        continue
                    send_packet = packet_bytes
                    src_ip = packet_bytes[12:16]
                    dst_ip = packet_bytes[16:20]
                    send_packet[12:16] = dst_ip
                    send_packet[16:20] = src_ip
                    send_packet[20] = 0
                    send_packet[22] = 0
                    send_packet[23] = 0
                    my_checksum = calculate_checksum(send_packet[20:])
                    send_packet[22] = (my_checksum >> 8) & 0xff
                    send_packet[23] = my_checksum & 0xff
                    send_ptr = wintun.WintunAllocateSendPacket(self.session, len(send_packet))
                    ffi.memmove(send_ptr, send_packet, len(send_packet))
                    wintun.WintunSendPacket(self.session, send_ptr)
                
            else:
                continue

    def dowm(self):
        log.info('Очистка драйверов')

        if hasattr(self, 'session') and self.session:
            wintun.WintunEndSession(self.session)
        if hasattr(self, 'adapter') and self.adapter:
            wintun.WintunCloseAdapter(self.adapter)
            wintun.WintunDeleteDriver()
        log.info('Очищено.')

    def get_packet(self):
        

class VPNClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport 
        log.info('Сокет клиента инициализирован.')
    
    def datagram_received(self, data, addr):
        self.tunnel.get_packet(data)

tunnel = WintunTunnel(ip_address='10.0.0.2', prefix_lenght=24, server_ip='1', server_port=2)

try:
    tunnel.up()
    tunnel.run_loop()
except KeyboardInterrupt:
    log.info('Завершение...')
finally:
    tunnel.dowm()
    log.info('Выключено.')

