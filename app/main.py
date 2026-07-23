from cdef import kernel, iphlp, wintun, ffi

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from asyncio.exceptions import CancelledError
import ipaddress
import logging
import asyncio
import socket
import struct
import os


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
        self._handshake_future = None
        self.current_token = None
        self.chacha = None
        self.session_id = None
        self.tx_counter = 0 
        self.rx_counter = 0
    
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
        getted_counter = struct.unpack('>Q', data[1:9])[0]
        if self.rx_counter < getted_counter:
            self.rx_counter = getted_counter
            nonce = b'\x00\x00\x00\x00' + data[1:9]
            decoded_data = self.chacha.decrypt(nonce, data[13:], None)
            send_ptr = wintun.WintunAllocateSendPacket(self.session, len(decoded_data))
            ffi.memmove(send_ptr, decoded_data, len(decoded_data))
            wintun.WintunSendPacket(self.session, send_ptr)
            log.info('Пакет получен.')
        else:
            log.info('Попытка атаки!')

    def _process_outgoing_packet(self):
        packet_size = ffi.new('DWORD *')
        while 1:
            packet_addr = wintun.WintunReceivePacket(self.session, packet_size)
            if packet_addr == ffi.NULL or packet_addr is None:
                break
            packet_bytes = bytes(ffi.buffer(packet_addr, packet_size[0]))
            log.debug('Пакет %s перехвачен.', len(packet_bytes))
            wintun.WintunReleaseReceivePacket(self.session, packet_addr)
            if hasattr(self, 'transport') and self.transport is not None:
                counter = struct.pack('>Q', self.tx_counter)
                nonce = b'\x00\x00\x00\x00' + counter
                encrypted_packet = self.chacha.encrypt(nonce, packet_bytes, None)
                packet_type = b'\x02'
                udp_payload = packet_type + self.session_id + counter + encrypted_packet
                self.tx_counter += 1
                self.async_loop.call_soon_threadsafe(self.transport.sendto, udp_payload, self.server_address)
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
            self._handshake_future = self.async_loop.create_future()
            byted_token  = os.urandom(4)
            numbered_token = struct.unpack('>I', byted_token)[0]
            self.current_token = numbered_token
            private_key = X25519PrivateKey.generate()
            client_byted_public_key = private_key.public_key().public_bytes_raw()
            handshake = b'\x01' + byted_token + client_byted_public_key
            self.transport.sendto(handshake, self.server_address)
            try:
                decrypted_settings = await asyncio.wait_for(self._handshake_future, timeout=5.0)
                if decrypted_settings[1:5] == byted_token:
                    self.session_id = decrypted_settings[5:9]
                    server_public_key_byted = decrypted_settings[9:41]
                    server_public_key = X25519PublicKey.from_public_bytes(server_public_key_byted)
                    shared_secret = private_key.exchange(server_public_key)
                    self.chacha = ChaCha20Poly1305(shared_secret)
                    os.system(f'New-NetIPAddress -InterfaceAlias {self.adapter_name} -IPAddress {decrypted_settings[41:]} -PrefixLength 16 -DefaultGateway 192.168.1.1')
                    log.info('Сессия установлена.')
                    await self.async_loop.run_in_executor(None, self._loop)
            except asyncio.TimeoutError:
                log.error('Превышено время ожидания, завершение сессии.')
                return
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
    def __init__(self, tunnel: WintunTunnel):
        self.tunnel = tunnel
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport 
        log.info('Сокет клиента инициализирован.')
    
    def datagram_received(self, data, addr):
        if data[0:1] == b'\x03':
            if self.tunnel._handshake_future and not self.tunnel._handshake_future.done():
                self.tunnel._handshake_future.set_result(data)
        else:
            self.tunnel._inject_packet(data)

tunnel = WintunTunnel(ip_address='10.0.0.2', prefix_lenght=16, server_ip='172.20.109.62', server_port=51820)

asyncio.run(tunnel.run_loop())
