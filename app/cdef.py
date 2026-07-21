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
