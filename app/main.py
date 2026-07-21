from cdef import kernel, iphlp, wintun, ffi
import logging
import ipaddress
import socket
import asyncio
from asyncio.exceptions import CancelledError


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
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
        self.transport = None
        self.async_loop = None
        self.running = False
    
    def up(self):
        row = ffi.new('MIB_UNICASTIPADDRESS_ROW *')
        luid = ffi.new('NET_LUID *')

        self.adapter = wintun.WintunCreateAdapter(self.adapter_name, self.pool_name, ffi.NULL)

        iphlp.InitializeUnicastIpAddressEntry(row)

        wintun.WintunGetAdapterLUID(self.adapter, luid)
        log.info('LUID: %s', luid.Value)
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
    
    def _inject_packet(self, data):
        send_ptr = wintun.WintunAllocateSendPacket(self.session, len(data))
        ffi.memmove(send_ptr, data, len(data))
        wintun.WintunSendPacket(self.session, send_ptr)
        log.info('Пакет получен.')

    def _process_outgoing_packet(self):
        packet_size = ffi.new('DWORD *')
        while 1:
            packet_addr = wintun.WintunReceivePacket(self.session, packet_size)
            if packet_addr == ffi.NULL or packet_addr is None:
                break
            packet_bytes = bytearray(ffi.buffer(packet_addr, packet_size[0]))
            log.debug('Пакет %s перехвачен.', len(packet_bytes))
            wintun.WintunReleaseReceivePacket(self.session, packet_addr)
            if hasattr(self, 'transport') and self.transport is not None:
                self.async_loop.call_soon_threadsafe(self.transport.sendto, bytes(packet_bytes), self.server_address)
            else: 
                log.info('Создание транспорта...')
                pass
    
    def _loop(self):
        self.running = True
        while self.running:
            if kernel.WaitForSingleObject(self.read_event, 100) == 0:
                self._process_outgoing_packet()
            else:
                continue
                    
    async def run_loop(self):
        self.async_loop = asyncio.get_running_loop()
        try:
            self.up()
            self.transport, protocol = await self.async_loop.create_datagram_endpoint(lambda: VPNClientProtocol(self), local_addr=('0.0.0.0', 0))
            await self.async_loop.run_in_executor(None, self._loop)
        except KeyboardInterrupt, CancelledError:
            log.info('Завершение работы...')
        finally:
            self.running = False
            await asyncio.sleep(0.1)
            if self.transport:
                self.transport.close()
            self.down()

    def down(self):
        log.info('Очистка драйверов')
        if hasattr(self, 'session') and self.session:
            wintun.WintunEndSession(self.session)
        if hasattr(self, 'adapter') and self.adapter:
            wintun.WintunCloseAdapter(self.adapter)
            wintun.WintunDeleteDriver()
        log.info('Очищено.')


class VPNClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport 
        log.info('Сокет клиента инициализирован.')
    
    def datagram_received(self, data, addr):
        self.tunnel.inject_packet(data)

tunnel = WintunTunnel(ip_address='10.0.0.2', prefix_lenght=24, server_ip='172.20.109.62', server_port=51820)

asyncio.run(tunnel.run_loop())

