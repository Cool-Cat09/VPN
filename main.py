from cffi import FFI

ffi = FFI()

ffi.cdef('''
    typedef void *HANDLE;
    typedef unsigned char BYTE;
    typedef unsigned long DWORD;
    typedef const wchar_t *LPCWSTR;
    typedef struct _GUID {
        unsigned long  Data1;
        unsigned short Data2;
        unsigned short Data3;
        unsigned char  Data4[8];
} GUID;
    typedef union _NET_LUID {
    uint64_t Value;
    struct {
        uint64_t Reserved : 24;
        uint64_t NetLuidIndex : 24;
        uint64_t IfType : 16;
    } Info;
    } NET_LUID;
    HANDLE WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
    void WintunCloseAdapter(HANDLE Adapter);
    extern void WintunGetAdapterLUID(HANDLE Adapter, NET_LUID *AnLuid);
    HANDLE WintunStartSession(HANDLE Adapter, DWORD Capacity);
    void WintunEndSession(HANDLE Session);
    HANDLE WintunGetReadWaitEvent(HANDLE Session);
    BYTE *WintunReceivePacket(HANDLE Session, DWORD *PacketSize);
    void WintunReleaseReceivePacket(HANDLE Session, BYTE *Packet);
    BYTE *WintunAllocateSendPacket(HANDLE Session, DWORD PacketSize);
    void WintunSendPacket(HANDLE Session, BYTE *Packet);
    void WintunDeleteDriver();
    
    typedef struct _IN_ADDR {
        union {
            struct { BYTE s_b1, s_b2, s_b3, s_b4; } S_un_b;
            uint32_t S_addr;
        } S_un;
    } IN_ADDR;

    typedef struct SOCKADDR_IN {
        short sin_family;
        unsigned short sin_port; 
        IN_ADDR sin_addr;   
        char sin_zero[8]; 
} SOCKADDR_IN;

    typedef union _SOCKADDR_INET {
        SOCKADDR_IN Ipv4;
        char pad[28]; 
} SOCKADDR_INET;
    typedef struct _MIB_UNICASTIPADDRESS_ROW {
        SOCKADDR_INET Address;      
        NET_LUID InterfaceLuid;
        unsigned long InterfaceIndex;
        int PrefixOrigin;
        int SuffixOrigin;     
        unsigned long ValidLifetime;  
        unsigned long PreferredLifetime;
        unsigned char OnLinkPrefixLength;
        unsigned char SkipAsSource;
        DWORD DadState;  
        DWORD ScopeId;
        long long CreationTimestamp;
} MIB_UNICASTIPADDRESS_ROW;
    DWORD CreateUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW *Row);
    void InitializeUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW *Row);
    extern DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
    ''')
    
wintun = ffi.dlopen('C://prj/VPN/wintun/bin/amd64/wintun.dll')
iphlp = ffi.dlopen('IPHLPAPI.dll')
kernel = ffi.dlopen('kernel32.dll')

requested_guid = ffi.new('GUID *')
adapter_name = ffi.new('wchar_t[]', 'CAdapter')
tunnel = ffi.new('wchar_t[]', 'Wintun')
luid = ffi.new('NET_LUID *')
row = ffi.new('MIB_UNICASTIPADDRESS_ROW *')

iphlp.InitializeUnicastIpAddressEntry(row)

adapter = wintun.WintunCreateAdapter(adapter_name, tunnel, requested_guid)
wintun.WintunGetAdapterLUID(adapter, luid)
print(luid.Value)
session = wintun.WintunStartSession(adapter, 0x4000000)
read_event = wintun.WintunGetReadWaitEvent(session)

row.InterfaceLuid.Value = luid.Value
row.Address.Ipv4.sin_family = 2
row.Address.Ipv4.sin_addr.S_un.S_addr = 0x0100000A
row.OnLinkPrefixLength = 24
row.SkipAsSource = 0
row.ValidLifetime = 0xffffffff
row.PreferredLifetime = 0xffffffff

def calculate_checksum(data):
    # Если длина нечетная, добавляем нулевой байт в конец для выравнивания
    if len(data) % 2 == 1:
        data += b'\x00'
    
    total = 0
    # Идем по массиву шагом в 2 байта
    for i in range(0, len(data), 2):
        # Собираем два байта в одно 16-битное число
        word = (data[i] << 8) + data[i+1]
        total += word
    
    # Схлопываем тридцать два бита в шестнадцать (перенос разрядов)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
        
    # Инвертируем биты и возвращаем результат
    return (~total) & 0xffff




result = iphlp.CreateUnicastIpAddressEntry(row)
print(f"==========================================")
print(f"Код ответа Windows API (Create IP): {result}")
print(f"==========================================")

packet_size = ffi.new('DWORD *')
while 1:
    if kernel.WaitForSingleObject(read_event, 100) == 0:
        while 1:
            packet_addr = wintun.WintunReceivePacket(session, packet_size)
            if packet_addr == ffi.NULL or packet_addr is None:
                break
            packet_bytes = bytearray(ffi.buffer(packet_addr, packet_size[0]))
            wintun.WintunReleaseReceivePacket(session, packet_addr)
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
            send_ptr = wintun.WintunAllocateSendPacket(session, len(send_packet))
            ffi.memmove(send_ptr, send_packet, len(send_packet))
            wintun.WintunSendPacket(session, send_ptr)
        

    else:
        continue

    

wintun.WintunDeleteDriver()