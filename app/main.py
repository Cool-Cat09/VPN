from cdef import kernel, iphlp, wintun, ffi

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from asyncio.exceptions import CancelledError
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from pathlib import Path
import subprocess
import ipaddress
import logging
import asyncio
import base64
import socket
import struct
import os

from create_keys import traffic_keys

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
console_log = logging.StreamHandler()
formatter = formatter = logging.Formatter("%(asctime)s - [%(name)s] - %(levelname)s - %(message)s")
console_log.setFormatter(formatter)
log.addHandler(console_log)

load_dotenv(Path(__file__).resolve().parent / '.env')

class WintunTunnel():
    def __init__(
            self, 
            prefix_lenght: int,
            server_ip: str,
            server_port: int,
            adapter_name: str = 'VPN',
            pool_name: str = 'Pool',
            ):
        self.client_private_key = X25519PrivateKey.from_private_bytes(base64.b64decode(Path(os.getenv('PRIVATE_KEY_PATH')).read_text(encoding='utf-8').strip()))
        self.client_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(Path(os.getenv('PUBLIC_KEY_PATH')).read_text(encoding='utf-8').strip()))
        self.server_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(Path(os.getenv('SERVER_PUBLIC_KEY')).read_text(encoding='utf-8').strip()))
        self.adapter_name = ffi.new('wchar_t[]', adapter_name)
        self.pool_name = ffi.new('wchar_t[]', pool_name)
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
        self.chacha_send = None
        self.chacha_recv = None
        self.session_id = None
        self.aad = None
        self.tx_counter = 0
        self.rx_counter = -1
    
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
        row.OnLinkPrefixLength = self.prefix_length
        row.SkipAsSource = 0
        row.ValidLifetime = 0xffffffff
        row.PreferredLifetime = 0xffffffff
        
        result = iphlp.CreateUnicastIpAddressEntry(row)
        log.info(f"Код ответа Windows API (Create IP): {result}")
    
    def _inject_packet(self, data):
        if len(data) < 29:
            log.info('Пакет поврежден.')
            return
        if data[0:1] != b'\x02':
            log.info('Пакет неизвестного типа.')
            return
        getted_counter = struct.unpack('>Q', data[5:13])[0]
        if getted_counter <= self.rx_counter:
            log.info('Повторный пакет!')
            return
        self.rx_counter = getted_counter
        nonce = b'\x00\x00\x00\x00' + data[5:13]
        decoded_data = self.chacha_recv.decrypt(nonce, data[13:], self.aad)
        send_ptr = wintun.WintunAllocateSendPacket(self.session, len(decoded_data))
        ffi.memmove(send_ptr, decoded_data, len(decoded_data))
        wintun.WintunSendPacket(self.session, send_ptr)
        log.info('Пакет получен.')
        return True

    def _process_outgoing_packet(self):
        packet_size = ffi.new('DWORD *')
        while 1:
            packet_addr = wintun.WintunReceivePacket(self.session, packet_size)
            if packet_addr == ffi.NULL or packet_addr is None:
                break
            packet_bytes = bytes(ffi.buffer(packet_addr, packet_size[0]))
            version = packet_bytes[0] >> 4
            if version != 4:
                log.debug('Пришел пакет не IPv4.')
                wintun.WintunReleaseReceivePacket(self.session, packet_addr)
                continue
            log.debug(packet_bytes)
            log.debug('Пакет %s перехвачен.', len(packet_bytes))
            wintun.WintunReleaseReceivePacket(self.session, packet_addr)
            if hasattr(self, 'transport') and self.transport is not None:
                counter = struct.pack('>Q', self.tx_counter)
                nonce_handshake = b'\x00\x00\x00\x00' + counter
                encrypted_packet = self.chacha_send.encrypt(nonce_handshake, packet_bytes, self.aad)
                packet_type = b'\x02'
                udp_payload = packet_type + self.session_id + counter + encrypted_packet
                self.tx_counter += 1
                self.async_loop.call_soon_threadsafe(self.transport.sendto, udp_payload, self.server_address)
                log.debug('Пакет отправлен на сервер.')
            else: 
                log.info('Создание транспорта...')
                pass
    
    def _loop(self):
        self.running = True
        while self.running:
            if kernel.WaitForSingleObject(self.read_event, 100) == 0:
                self._process_outgoing_packet()
            if not self.running:
                break
            else:
                continue
                    
    async def run_loop(self):
        self.async_loop = asyncio.get_running_loop()
        self.up()
        try:
            self.transport, protocol = await self.async_loop.create_datagram_endpoint(lambda: VPNClientProtocol(self), local_addr=('0.0.0.0', 0))
            self._handshake_future = self.async_loop.create_future()
            byted_token  = os.urandom(4)
            numbered_token = struct.unpack('>I', byted_token)[0]
            self.current_token = numbered_token
            private_key = X25519PrivateKey.generate()
            shared_secret_handshake = private_key.exchange(self.server_public_key)
            chacha_handshake = ChaCha20Poly1305(shared_secret_handshake)
            client_public_key_byted = private_key.public_key().public_bytes_raw()
            nonce0 = b'\x00' * 12
            nonce1 = b'\x00' * 11 + b'\x01'
            nonce2 = b'\x00' * 11 + b'\x02'
            aad01 = b'\x01' + client_public_key_byted
            byted_token_encrypt = chacha_handshake.encrypt(nonce0, byted_token, aad01)
            client_public_key_handshake_byted = self.client_public_key.public_bytes_raw()
            client_public_key_handshake_encrypt = chacha_handshake.encrypt(
                nonce1, client_public_key_handshake_byted, aad01
            )
            handshake = b'\x01' + byted_token_encrypt + client_public_key_byted + client_public_key_handshake_encrypt
            self.transport.sendto(handshake, self.server_address)
            try:
                decrypted_settings = await asyncio.wait_for(self._handshake_future, timeout=10.0)
                if len(decrypted_settings) < 141:
                    log.error('Handshake-ответ слишком короткий.')
                    return
                token_ct = decrypted_settings[1:21]
                server_eph = decrypted_settings[41:73]
                aad03 = b'\x03' + token_ct + server_eph
                if token_ct != byted_token_encrypt:
                    log.error('Handshake-ответ с чужим token.')
                    return
                server_public_key_handshake_decrypt = chacha_handshake.decrypt(
                    nonce2, decrypted_settings[93:141], aad03
                )
                server_public_key_handshake = X25519PublicKey.from_public_bytes(server_public_key_handshake_decrypt)
                server_public_key = X25519PublicKey.from_public_bytes(server_eph)
                dh1 = private_key.exchange(server_public_key)
                dh2 = self.client_private_key.exchange(server_public_key)
                dh3 = private_key.exchange(server_public_key_handshake)
                ikm = dh1 + dh2 + dh3
                self.chacha_send, self.chacha_recv = traffic_keys(ikm)
                self.session_id = chacha_handshake.decrypt(nonce0, decrypted_settings[21:41], aad03)
                self.aad = b'\x02' + self.session_id
                ip = chacha_handshake.decrypt(nonce1, decrypted_settings[73:93], aad03)
                ip = socket.inet_ntoa(ip)
                clean_ip = "".join(ip.split()).strip()
                log.info(ip)
                set_command = f'netsh interface ipv4 set address name="VPN" source=static {clean_ip} 255.255.0.0 f{clean_ip}'
                subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'dns', 'name="VPN"', 'source=static', 'address=8.8.8.8'], check=True, capture_output=True)
                subprocess.run(set_command, capture_output=True, text=True, shell=True)
                subprocess.run(['route', 'add', '0.0.0.0', 'mask', '128.0.0.0', f'{clean_ip}'])
                subprocess.run(['route', 'add', '128.0.0.0', 'mask', '128.0.0.0', f'{clean_ip}'])
                log.info('Сессия установлена.')
                await self.async_loop.run_in_executor(None, self._loop)
            except asyncio.TimeoutError:
                log.error('Превышено время ожидания, завершение сессии.')
                return
            except InvalidTag:
                log.error('Handshake: неверная AEAD-метка.')
                return
        except (KeyboardInterrupt, CancelledError):
            log.info('Завершение работы...')
        finally:
            self.running = False
            await asyncio.sleep(0.1)
            if self.transport:
                self.transport.close()
            self.down()

    def down(self):
        log.info('Очистка...')
        self.running = False
        if hasattr(self, 'read_event') and self.read_event:
            kernel.SetEvent(self.read_event)
        if hasattr(self, 'session') and self.session:
            wintun.WintunEndSession(self.session)
        if hasattr(self, 'adapter') and self.adapter:
            wintun.WintunCloseAdapter(self.adapter)
        log.info('Очищено.')

class VPNClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnel: WintunTunnel):
        self.tunnel = tunnel
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport 
        log.info('Сокет клиента инициализирован.')
    
    def datagram_received(self, data, addr):
        if data[0:1] == b'\x03' and self.tunnel.server_address == addr:
            if self.tunnel._handshake_future and not self.tunnel._handshake_future.done():
                self.tunnel._handshake_future.set_result(data)
        else:
            self.tunnel.async_loop.run_in_executor(None, self.tunnel._inject_packet, data)

tunnel = WintunTunnel(prefix_lenght=16, server_ip=os.getenv('SERVER_IP'), server_port=int(os.getenv('SERVER_PORT')))

if __name__ == '__main__':
    try:
        asyncio.run(tunnel.run_loop())
    except KeyboardInterrupt:
        log.info('Работа завершена.')
