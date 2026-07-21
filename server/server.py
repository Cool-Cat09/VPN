import asyncio 
import logging
import os
import struct
import fcntl

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
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

class VPNServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, tun):
        self.tun = tun
        self.transport = None
        self.clients_addrs = dict()

    def connection_made(self, transport):
        self.transport = transport
        log.info('Сокет запущен.')
    
    def datagram_received(self, data, addr):
        log.info('Пакет %i от %s', len(data), addr)
        client_ip = data[12:16]
        self.clients_addrs[client_ip] = addr
        os.write(self.tun, data)

async def main():
    loop = asyncio.get_running_loop()
    tun = await create_tun()
    log.info("Автоматически активируем интерфейс tun0...")
    os.system("ip link set dev tun0 up")
    os.system("ip addr add 10.0.0.1/24 dev tun0")
    log.info("Интерфейс tun0 готов к приему трафика.")
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: VPNServerProtocol(tun),
        local_addr=('0.0.0.0', 51820)
    )
    
    def handle_run_read():
        packet = os.read(tun, 2048)
        log.info('Пакет %s получен', len(packet))
        client_addr = packet[16:20]
        if protocol.clients_addrs.get(client_addr):
            transport.sendto(packet, protocol.clients_addrs[client_addr])
            log.info('Ответ отправлен по UDP обратно клиенту на %s.', protocol.clients_addrs)
        else:
            log.warning('Пакет из TUN получен, но адрес Windows-клиента еще неизвестен (нет входящих UDP сообщений).')

    loop.add_reader(tun, handle_run_read)
    
    try:
        while 1:
            await asyncio.sleep(3600)
    finally:
        loop.remove_reader(tun)
        transport.close()
        os.close(tun)
        log.info('Работа завершена.')

try:
    asyncio.run(main())
except KeyboardInterrupt:
        log.info('Завершение...')