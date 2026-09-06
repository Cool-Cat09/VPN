import pytest

from app.create_keys import traffic_keys
from app.main import WintunTunnel

@pytest.fixture
def create_chacha_keys():

    return traffic_keys(b'\x00'*96)

@pytest.fixture
def encrypt_data(create_chacha_keys):
    recv, send = create_chacha_keys
    nonce = b'\x00'*4 + b'\x00'*7 + b'\xff'
    data = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff'*3
    aad = b'\x00'*12
    encrypt_data = recv.encrypt(nonce, data, aad)
    packet = b'\x02'*5 + b'\x00'*7 + b'\xff' + encrypt_data

    return packet

@pytest.fixture
def mock_wintun(create_chacha_keys, mocker):
    mocker.patch('app.main.wintun')
    mocker.patch('app.main.iphlp')
    mocker.patch('app.main.ffi')
    mocker.patch('app.main.log')

    obj = WintunTunnel(prefix_lenght=16, server_ip='127.0.0.1', server_port=0)
    
    send, recv = create_chacha_keys

    obj.rx_counter = 14
    obj.chacha_recv = send
    obj.chacha_send = recv
    obj.aad = b'\x00'*12
    obj.session = b'\x00'*4

    return obj
    