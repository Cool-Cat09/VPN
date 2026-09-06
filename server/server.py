from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from pathlib import Path
from dotenv import load_dotenv
import subprocess
import argparse
import asyncio 
import logging
import base64
import socket
import struct
import fcntl
import os

from create_keys import traffic_keys


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
console_log = logging.StreamHandler()
formatter = formatter = logging.Formatter("%(asctime)s - [%(name)s] - %(levelname)s - %(message)s")
console_log.setFormatter(formatter)
log.addHandler(console_log)

load_dotenv(Path(__file__).resolve().parent / '.env')

parser = argparse.ArgumentParser()
server_ip = parser.add_argument('-b', '--bind', type=str, required=True, help='server ip address')
server_port = parser.add_argument('-p', '--port', type=int, required=True, help='server port')
args = parser.parse_args()

async def create_tun(tun_name: str = 'tun0'):
    tun = os.open('/dev/net/tun', os.O_RDWR)
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    flags = IFF_TUN | IFF_NO_PI
    ifr = struct.pack("16sH", tun_name.encode('utf-8'), flags)
    TUNSETIFF = 0x400454ca
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

class Server():
    def __init__(self):
        self.server_private_key = X25519PrivateKey.from_private_bytes(base64.b64decode(Path(os.getenv('PRIVATE_KEY_PATH')).read_text(encoding='utf-8').strip()))
        self.server_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(Path(os.getenv('PUBLIC_KEY_PATH')).read_text(encoding='utf-8').strip()))
        self.server_ip = args.bind
        self.server_port = args.port
        self._clients_addrs = dict()
        self._sessions_addrs = dict()
        self._ip_pool = asyncio.Queue()
        self._sessions_id_pool = asyncio.Queue()

    async def _create_ip_pool(self):
        for x in range(256):
            for y in range(255):
                if x == 0 and y <= 2:
                    continue
                available_address = f'10.0.{x}.{y}'
                self._ip_pool.put_nowait(available_address)
        log.info(f'Пул айпи адресов заполнен. Последний адрес: 10.0.{x}.{y}')

    async def _create_session_id_pool(self):
        for id in range(1, 65537):
            self._sessions_id_pool.put_nowait(id)
        log.info(f'Пул айди сессий заполнен. Последний айди: {id}.')

    async def up(self):
        loop = asyncio.get_running_loop()
        tun = await create_tun()
        os.set_blocking(tun, False)
        log.info('Автоматически активируем интерфейс tun0...')
        subprocess.run(['ip', 'link', 'set', 'dev', 'tun0', 'up'], check=True, capture_output=True)
        subprocess.run(['ip', 'route', 'add', '10.0.0.0/16', 'dev', 'tun0'], check=True, capture_output=True)
        log.info('Интерфейс tun0 готов к приему трафика.')
        for param in ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter", "net.ipv4.conf.tun0.rp_filter"]:
            proc = await asyncio.create_subprocess_exec("sysctl", "-w", f"{param}=0")
            await proc.wait()
        log.info("Проверка обратного пути (rp_filter) успешно отключена.")
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: VPNServerProtocol(tun, self),
            local_addr=(self.server_ip, self.server_port)
        )

        await self._create_ip_pool()
        await self._create_session_id_pool()
        
        def _handle_run_read():
            log.debug('Вызов handle_run_read.')
            try:
                data = os.read(tun, 2048)
                log.info('Пакет %s получен', len(data))
                client_addr = data[16:20]
                session = self._clients_addrs.get(client_addr)
                if session:
                    session_id = self._clients_addrs.get(client_addr).get('byted_session')
                    ip = session.get('eth_ip')
                    counter = struct.pack('>Q', session.get('tx_counter'))
                    session['tx_counter'] = session.get('tx_counter') + 1
                    chacha = session.get('chacha_send')
                    nonce = b'\x00\x00\x00\x00' + counter
                    aad = b'\x02' + session_id
                    encrypted_data = chacha.encrypt(nonce, data, aad)
                    packet = b'\x02' + struct.pack('>I', session['session_id']) + counter + encrypted_data
                    transport.sendto(packet, ip)
                    log.info('Ответ отправлен по UDP обратно клиенту на %s.', ip)
                else:
                    log.warning('Пакет из TUN получен, но адрес Windows-клиента еще неизвестен (нет входящих UDP сообщений).')
            except BlockingIOError:
                return
            
        loop.add_reader(tun, _handle_run_read)
        
        try:
            while 1:
                await asyncio.sleep(3600)
        finally:
            loop.remove_reader(tun)
            transport.close()
            os.close(tun)
            log.info('Работа завершена.')

class VPNServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, tun, server: Server):
        self.__server = server
        self._tun = tun
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport
        log.info('Сокет запущен.')
    
    def datagram_received(self, data, addr):
        try:
            self._datagram_received(data, addr)
        except InvalidTag:
            log.warning('Неверная AEAD-метка от %s, пакет отброшен.', addr)
        except Exception:
            log.exception('Ошибка разбора датаграммы от %s', addr)

    def _datagram_received(self, data, addr):
        if data[:1] == b'\x01':
            if len(data) < 101:
                log.warning('Handshake слишком короткий.')
                return
            private_key = X25519PrivateKey.generate()
            client_byted_public_key = data[21:53]
            client_public_key = X25519PublicKey.from_public_bytes(client_byted_public_key)
            es = self.__server.server_private_key.exchange(client_public_key)
            chacha_handshake = ChaCha20Poly1305(es)
            nonce0 = b'\x00' * 12
            nonce1 = b'\x00' * 11 + b'\x01'
            nonce2 = b'\x00' * 11 + b'\x02'
            server_public_key_byted = private_key.public_key().public_bytes_raw()
            client_public_key_handshake_encrypt = data[53:101]
            aad01 = b'\x01' + client_byted_public_key
            client_public_key_handshake = X25519PublicKey.from_public_bytes(
                chacha_handshake.decrypt(nonce1, client_public_key_handshake_encrypt, aad01)
            )
            dh1 = private_key.exchange(client_public_key)
            dh2 = private_key.exchange(client_public_key_handshake)
            dh3 = es
            ikm = dh1 + dh2 + dh3
            chacha_recv, chacha_send = traffic_keys(ikm)
            try:
                client_addr: str = self.__server._ip_pool.get_nowait()
                client_addr = socket.inet_aton(client_addr)
            except asyncio.QueueEmpty:
                log.error("Пул IP адресов пуст!")
                return
            log.info(client_addr)
            token_encrypt = data[1:21]
            aad03 = b'\x03' + token_encrypt + server_public_key_byted
            client_addr_encrypt = chacha_handshake.encrypt(nonce1, client_addr, aad03)
            try:
                session = self.__server._sessions_id_pool.get_nowait()
            except asyncio.QueueEmpty:
                log.error('Пул session id пуст!')
                return
            byted_session = struct.pack('>I', session)
            session_encrypt = chacha_handshake.encrypt(nonce0, byted_session, aad03)
            public_key_handshake_byted = self.__server.server_public_key.public_bytes_raw()
            public_key_handshake_encrypt = chacha_handshake.encrypt(
                nonce2, public_key_handshake_byted, aad03
            )
            handshake = (
                b'\x03'
                + token_encrypt
                + session_encrypt
                + server_public_key_byted
                + client_addr_encrypt
                + public_key_handshake_encrypt
            )
            self._transport.sendto(handshake, addr)
            client_info = {
                'chacha_recv': chacha_recv,
                'chacha_send': chacha_send,
                'eth_ip': addr,
                'local_ip': client_addr,
                'session_id': session,
                'byted_session': byted_session,
                'tx_counter': 0,
                'rx_counter': -1,
            }
            self.__server._clients_addrs[client_addr] = client_info
            self.__server._sessions_addrs[session] = client_info
            log.info('Сессия установлена.')
        else:
            if len(data) < 29 or data[:1] != b'\x02':
                log.warning('Пакет поврежден.')
                return
            nonce = b'\x00\x00\x00\x00' + data[5:13]
            session = struct.unpack('>I', data[1:5])[0]
            session_info = self.__server._sessions_addrs.get(session)
            if session_info is None:
                log.warning('Неизвестная сессия %s', session)
                return
            aad = b'\x02' + session_info['byted_session']
            encrypted_packet = data[13:]
            decrypted_packet = session_info['chacha_recv'].decrypt(nonce, encrypted_packet, aad)
            counter = struct.unpack('>Q', data[5:13])[0]
            if counter <= session_info['rx_counter']:
                log.debug('Повторный пакет.')
                return
            session_info['rx_counter'] = counter
            session_info['eth_ip'] = addr
            log.debug(f'Расшифрованный пакет: {decrypted_packet}')
            log.info('Пакет %i от %s', len(data), addr)
            log.debug('Запись в виртуальный сетевой адаптер.')
            os.write(self._tun, decrypted_packet)
            log.debug('Запись прошла успешно.')
server = Server()

if __name__ == '__main__':
    try:
        asyncio.run((server.up()))
    except KeyboardInterrupt:
            log.info('Завершение...')