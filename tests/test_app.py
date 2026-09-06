from unittest.mock import MagicMock
import subprocess
import pytest
import struct

from app.main import WintunTunnel, VPNClientProtocol

from conftest import create_chacha_keys, encrypt_data, mock_wintun

def test_create_wintun():
    wintun = WintunTunnel(prefix_lenght=16, server_ip='127.0.0.1', server_port=0)

    assert wintun.client_private_key != None
    assert wintun.client_public_key != None
    assert wintun.server_public_key != None
    assert wintun.adapter_name != None
    assert wintun.pool_name != None
    assert wintun.server_address != None

def test_wintun_up():
    wintun = WintunTunnel(prefix_lenght=16, server_ip='127.0.0.1', server_port=0)
    wintun.up()

    assert subprocess.run(['powershell', '-Command', 'Get-NetAdapter', '-Name', 'VPN']).returncode == 0

def test_wintun_down():
    wintun = WintunTunnel(prefix_lenght=16, server_ip='127.0.0.1', server_port=0)
    wintun.up()
    wintun.down()

    assert subprocess.run(['powershell', '-Command', 'Get-NetAdapter', '-Name', 'VPN']).returncode == 1

@pytest.mark.parametrize(
    'data',
    [
        (b'\x00'),
        (b'\x01'*30),
        (b'\x02'*5),
    ]
)
def test_no_data_inject_packet(data, mock_wintun):
    data = data + struct.pack('>Q', 10) + b'\x00' * 17
    result = WintunTunnel._inject_packet(mock_wintun, data)

    assert result == None

def test_inject_packet(mock_wintun, encrypt_data):
    result = WintunTunnel._inject_packet(mock_wintun, encrypt_data)

    assert result == True

def test_datagram_receive_handshake():
    mock_tunnel = MagicMock()

    mock_tunnel.server_address = ('192.168.1.5', 60000)
    mock_tunnel.rx_counter = -1
    mock_tunnel._handshake_future.done.return_value = False

    mock_loop = MagicMock()
    mock_tunnel.async_loop = mock_loop

    protocol = VPNClientProtocol(mock_tunnel)

    test_data = b'\x03' + b'some_encrypted_payload'
    sender_addr = ('192.168.1.5', 60000)
    
    protocol.datagram_received(test_data, sender_addr)

    mock_tunnel._handshake_future.set_result.assert_called_once_with(test_data)

def test_datagram_receive():
    mock_tunnel = MagicMock()

    mock_tunnel.server_address = ('127.0.0.1', 0)
    mock_tunnel.rx_counter = -1
    mock_tunnel._handshake_future = None

    mock_loop = MagicMock()
    mock_tunnel.async_loop = mock_loop

    protocol = VPNClientProtocol(mock_tunnel)

    test_data = b'\x02' + b'some_encrypted_payload'
    sender_addr = ("192.168.1.5", 60000)
    
    protocol.datagram_received(test_data, sender_addr)

    mock_loop.run_in_executor.assert_called_once_with(
        None,                    
        mock_tunnel._inject_packet, 
        test_data                
    )
