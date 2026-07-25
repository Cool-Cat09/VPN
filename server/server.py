from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import asyncio 
import logging
import socket
import struct
import fcntl
import os

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
console_log = logging.StreamHandler()
formatter = formatter = logging.Formatter("%(asctime)s - [%(name)s] - %(levelname)s - %(message)s")
console_log.setFormatter(formatter)
log.addHandler(console_log)

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
        self.clients_addrs = dict()
        self.sessions_addrs = dict()
        self.ip_pool = asyncio.Queue()
        self.sessions_id_pool = asyncio.Queue()

    async def _create_ip_pool(self):
        for x in range(256):
            for y in range(255):
                if x == 0 and y <= 1:
                    continue
                available_address = f'10.0.{x}.{y}'
                self.ip_pool.put_nowait(available_address)
        log.info(f'Пул айпи адресов заполнен. Последний адрес: 10.0.{x}.{y}')

    async def _create_session_id_pool(self):
        for id in range(1, 65537):
            self.sessions_id_pool.put_nowait(id)
        log.info(f'Пул айди сессий заполнен. Последний айди: {id}.')

    async def up(self):
        loop = asyncio.get_running_loop()
        tun = await create_tun()
        os.set_blocking(tun, False)
        log.info('Автоматически активируем интерфейс tun0...')
        os.system('sudo ip link set dev tun0 up')
        os.system('sudo ip addr add 10.0.0.1 peer 10.0.0.2 dev tun0')
        os.system('sudo ip route add 10.0.0.0/16 dev tun0')
        os.system('sudo ip route add 10.0.0.1/16 dev tun0')
        log.info('Интерфейс tun0 готов к приему трафика.')
        for param in ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter", "net.ipv4.conf.tun0.rp_filter"]:
            proc = await asyncio.create_subprocess_exec("sysctl", "-w", f"{param}=0")
            await proc.wait()
        log.info("Проверка обратного пути (rp_filter) успешно отключена.")
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: VPNServerProtocol(tun, self),
            local_addr=('0.0.0.0', 51820)
        )

        await self._create_ip_pool()
        await self._create_session_id_pool()
        
        def _handle_run_read():
            log.debug('Вызов handle_run_read.')
            try:
                data = os.read(tun, 2048)
                log.info('Пакет %s получен', len(data))
                client_addr = data[16:20]
                session = self.clients_addrs.get(client_addr)
                if session:
                    ip = session.get('eth_ip')
                    counter = struct.pack('>Q', session.get('tx_counter'))
                    session['tx_counter'] = session.get('tx_counter') + 1
                    chacha = session.get('chacha')
                    nonce = b'\x00\x00\x00\x00' + counter
                    encrypted_data = chacha.encrypt(nonce, data, None)
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
        self.server = server
        self.tun = tun
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        log.info('Сокет запущен.')
    
    def datagram_received(self, data, addr):
        if data[:1] == b'\x01':
            private_key = X25519PrivateKey.generate()
            server_byted_public_key = private_key.public_key().public_bytes_raw()
            client_byted_public_key = data[5:37]
            client_public_key = X25519PublicKey.from_public_bytes(client_byted_public_key)
            shared_secret = private_key.exchange(client_public_key)
            chacha = ChaCha20Poly1305(shared_secret)
            client_addr: str = self.server.ip_pool.get_nowait()
            client_addr = socket.inet_aton(client_addr)
            log.info(client_addr)
            byted_token = data[1:5]
            nonce = b'\x00\x00\x00\x00' + byted_token + b'\x00\x00\x00\x00'
            encoded_client_addr = chacha.encrypt(nonce, client_addr, None)
            session = self.server.sessions_id_pool.get_nowait()
            byted_session = struct.pack('>I', session)
            handshake = b'\x03' + byted_token + byted_session + server_byted_public_key + encoded_client_addr
            self.transport.sendto(handshake, addr)
            client_info = {'chacha': chacha, 'eth_ip': addr, 'local_ip': client_addr, 'session_id': session, 'tx_counter': 0} 
            self.server.clients_addrs[client_addr] = client_info
            self.server.sessions_addrs[session] = client_info
            log.info('Сессия установлена.')   
        else:
            nonce = b'\x00\x00\x00\x00' + data[5:13]
            byted_session = data[1:5]
            session = struct.unpack('>I', byted_session)[0]
            encrypted_packet = data[13:]
            decrypted_packet = self.server.sessions_addrs[session]['chacha'].decrypt(nonce, encrypted_packet, None)
            counter = decrypted_packet[1:9]
            self.server.sessions_addrs[session]['counter'] = counter
            self.server.sessions_addrs[session]['eth_ip'] = addr
            log.debug(f'Расшифрованный пакет: {decrypted_packet}')
            log.info('Пакет %i от %s', len(data), addr)
            log.debug('Запись в виртуальный сетевой адаптер.')
            os.write(self.tun, decrypted_packet)
            log.debug('Запись прошла успешно.')
server = Server()
try:
    asyncio.run((server.up()))
except KeyboardInterrupt:
        log.info('Завершение...')