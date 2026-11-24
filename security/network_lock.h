// Persistent deny rules survive application exit. All exceptions for the tunnel
// live in a dynamic WFP session, automatically removed when this guard exits.
static constexpr GUID policy={0x5d582cea,0xde43,0x4517,{0x91,0x67,0xc4,0x77,0xb1,0x7e,0x39,0xd0}};
static const GUID* layers[]={&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
    &FWPM_LAYER_OUTBOUND_IPPACKET_V4,&FWPM_LAYER_OUTBOUND_IPPACKET_V6};
GUID filter_key(unsigned layer,unsigned slot){auto key=policy;key.Data1+=1+layer*8+slot;return key;}
struct Engine {
    HANDLE h=nullptr;
    explicit Engine(bool dynamic){
        FWPM_SESSION0 session{};session.flags=dynamic?FWPM_SESSION_FLAG_DYNAMIC:0;
        session.txnWaitTimeoutInMSec=6000;
        checked(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&h));
    }
    ~Engine(){if(h)FwpmEngineClose0(h);}
};
struct Transaction {
    HANDLE engine;bool complete=false;
    explicit Transaction(HANDLE e):engine(e){checked(FwpmTransactionBegin0(e,0));}
    ~Transaction(){if(!complete)FwpmTransactionAbort0(engine);}
    void commit(){checked(FwpmTransactionCommit0(engine));complete=true;}
};
void remove_rule(HANDLE engine,unsigned layer,unsigned slot){
    auto key=filter_key(layer,slot);DWORD rc=FwpmFilterDeleteByKey0(engine,&key);
    if(rc!=FWP_E_FILTER_NOT_FOUND)checked(rc);
}
void add_rule(HANDLE engine,unsigned layer,unsigned slot,bool persistent,
              std::vector<FWPM_FILTER_CONDITION0> conds={}){
    FWPM_FILTER0 f{};f.filterKey=filter_key(layer,slot);f.layerKey=*layers[layer];f.subLayerKey=policy;
    f.displayData.name=const_cast<wchar_t*>(L"FLURUX Network Lock");
    f.flags=persistent?FWPM_FILTER_FLAG_PERSISTENT:0;
    f.action.type=slot?FWP_ACTION_PERMIT:FWP_ACTION_BLOCK;
    UINT64 rank=slot+1;f.weight.type=FWP_UINT64;f.weight.uint64=&rank;
    f.numFilterConditions=static_cast<UINT32>(conds.size());f.filterCondition=conds.data();
    checked(FwpmFilterAdd0(engine,&f,nullptr,nullptr));
}
FWPM_FILTER_CONDITION0 cond(const GUID& key,FWP_DATA_TYPE type){
    FWPM_FILTER_CONDITION0 c{};c.fieldKey=key;c.matchType=FWP_MATCH_EQUAL;c.conditionValue.type=type;return c;
}
void begin_policy(HANDLE engine){
    Transaction tx(engine);FWPM_SUBLAYER0 sub{};sub.subLayerKey=policy;
    sub.displayData.name=const_cast<wchar_t*>(L"FLURUX Network Lock");sub.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;sub.weight=0x4000;
    auto rc=FwpmSubLayerAdd0(engine,&sub,nullptr);if(rc!=FWP_E_ALREADY_EXISTS)checked(rc);
    for(unsigned i=0;i<std::size(layers);++i){
        remove_rule(engine,i,0);remove_rule(engine,i,1);add_rule(engine,i,0,true);
        auto local=cond(FWPM_CONDITION_FLAGS,FWP_UINT32);
        local.matchType=FWP_MATCH_FLAGS_ALL_SET;local.conditionValue.uint32=FWP_CONDITION_FLAG_IS_LOOPBACK;
        add_rule(engine,i,1,true,{local});
    }
    tx.commit();
}
struct PolicyMutex {
    Handle mutex;
    PolicyMutex():mutex(CreateMutexW(nullptr,FALSE,L"Global\\FLURUX-Network-Lock-5d582cea")){
        require(mutex.h!=nullptr);auto rc=WaitForSingleObject(mutex.h,0);
        require(rc==WAIT_OBJECT_0 || rc==WAIT_ABANDONED,ERROR_BUSY);
    }
    ~PolicyMutex(){ReleaseMutex(mutex.h);}
};
void unlock_network(){
    PolicyMutex lock;Engine engine(false);Transaction tx(engine.h);
    for(unsigned i=0;i<std::size(layers);++i){remove_rule(engine.h,i,0);remove_rule(engine.h,i,1);}
    auto rc=FwpmSubLayerDeleteByKey0(engine.h,&policy);if(rc!=FWP_E_SUBLAYER_NOT_FOUND)checked(rc);
    tx.commit();
}
void network_lock(Signals& signals,const wstring& ip,const wstring& port,const wstring& alias,const wstring& exe){
    require(alias.size()==19 && alias.substr(0,7)==L"FLURUX-" && alias.find_first_not_of(L"0123456789abcdef",7)==wstring::npos);
    require(!port.empty() && port.size()<=5 && port.find_first_not_of(L"0123456789")==wstring::npos);
    unsigned long number=std::stoul(port);require(number>0 && number<=65535);
    IN_ADDR v4{};FWP_BYTE_ARRAY16 v6{};bool ipv4=InetPtonW(AF_INET,ip.c_str(),&v4)==1;
    require(ipv4 || InetPtonW(AF_INET6,ip.c_str(),v6.byteArray16)==1);
    auto expected=installed().parent_path()/L"engines"/L"sing-box"/L"sing-box.exe";
    auto preview=installed().parent_path()/L"engines"/L"sing-box-preview"/L"sing-box.exe";
    auto path=fs::path(exe);require(path==expected || path==preview);
    secure(path.parent_path().parent_path());secure(path.parent_path());secure(path);
    FWP_BYTE_BLOB* id=nullptr;checked(FwpmGetAppIdFromFileName0(path.c_str(),&id));
    PolicyMutex lock;Engine persistent(false);Engine session(true);
    begin_policy(persistent.h);
    {
        Transaction tx(session.h);
        for(unsigned i=ipv4?0:1;i<std::size(layers);i+=2){
            auto addr=cond(FWPM_CONDITION_IP_REMOTE_ADDRESS,ipv4?FWP_UINT32:FWP_BYTE_ARRAY16_TYPE);
            if(ipv4)addr.conditionValue.uint32=ntohl(v4.S_un.S_addr);else addr.conditionValue.byteArray16=&v6;
            std::vector<FWPM_FILTER_CONDITION0> cs{addr};
            if(i<4){auto dest=cond(FWPM_CONDITION_IP_REMOTE_PORT,FWP_UINT16);dest.conditionValue.uint16=static_cast<UINT16>(number);cs.push_back(dest);}
            if(i<2){auto program=cond(FWPM_CONDITION_ALE_APP_ID,FWP_BYTE_BLOB_TYPE);program.conditionValue.byteBlob=id;cs.push_back(program);}
            add_rule(session.h,i,2,false,cs);
        }
        tx.commit();
    }
    FwpmFreeMemory0(reinterpret_cast<void**>(&id));
    require(SetEvent(signals.ready.h)!=FALSE);
    HANDLE waits[]={signals.parent.h,signals.stop.h};UINT64 active=0;
    for(;;){
        auto state=WaitForMultipleObjects(2,waits,FALSE,150);
        if(state!=WAIT_TIMEOUT){require(state==WAIT_OBJECT_0 || state==WAIT_OBJECT_0+1);break;}
        NET_LUID luid{};if(ConvertInterfaceAliasToLuid(alias.c_str(),&luid)!=NO_ERROR)luid.Value=0;
        if(luid.Value==active)continue;
        Transaction tx(session.h);
        for(unsigned i=0;i<std::size(layers);++i){
            if(active)remove_rule(session.h,i,3);
            if(luid.Value){auto tunnel=cond(FWPM_CONDITION_IP_LOCAL_INTERFACE,FWP_UINT64);
                tunnel.conditionValue.uint64=&luid.Value;add_rule(session.h,i,3,false,{tunnel});}
        }
        tx.commit();active=luid.Value;
    }
}
