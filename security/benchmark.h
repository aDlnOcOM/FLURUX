#pragma once
// A diagnostic lease can run only one of the fixed compatibility profiles at a time.
// No caller-supplied executable, Lua, file path or free-form arguments.
inline int benchmark(const fs::path& dir,Signals& signals,const wstring& nonce,
                     const wstring& domains,const wstring& excluded){
    require(domains_ok(domains) && (excluded==L"-" || domains_ok(excluded)));
    auto prefix=L"Local\\FLURUX-"+nonce;
    Handle request(OpenEventW(SYNCHRONIZE,FALSE,(prefix+L"-request").c_str()));
    Handle quit(OpenEventW(SYNCHRONIZE,FALSE,(prefix+L"-quit").c_str()));
    Handle done(OpenEventW(EVENT_MODIFY_STATE,FALSE,(prefix+L"-done").c_str()));
    Handle mem(OpenFileMappingW(FILE_MAP_READ|FILE_MAP_WRITE,FALSE,(prefix+L"-slot").c_str()));
    require(request.h && quit.h && done.h && mem.h,ERROR_INVALID_HANDLE);
    auto slot=static_cast<volatile LONG*>(MapViewOfFile(mem.h,FILE_MAP_READ|FILE_MAP_WRITE,0,0,8));
    require(slot!=nullptr,ERROR_INVALID_HANDLE);
    struct View {const volatile void* p;~View(){UnmapViewOfFile(const_cast<const void*>(p));}} view{slot};
    const wchar_t* methods[]={L"split",L"disorder",L"quic",L"disorder_quic"};
    const wchar_t* families[]={L"both",L"ipv4",L"ipv6"};
    const wchar_t* ports[]={L"443",L"8443",L"9443",L"443,8443",L"443,8443,9443"};
    HANDLE waits[]={signals.parent.h,quit.h,request.h};
    for(;;){
        DWORD event=WaitForMultipleObjects(3,waits,FALSE,INFINITE);
        if(event==WAIT_OBJECT_0 || event==WAIT_OBJECT_0+1)return 0;
        require(event==WAIT_OBJECT_0+2);
        DWORD rc=0;
        try {
            LONG index=InterlockedCompareExchange(slot,0,0);
            require(index>=0 && index<60);
            auto scope=ports[index%5];
            rc=zapret(dir,signals,methods[index/15],domains,excluded,scope,scope,families[(index/5)%3]);
        }catch(DWORD code){rc=code?code:ERROR_INVALID_DATA;}
        catch(const fs::filesystem_error& e){rc=e.code().value()?e.code().value():ERROR_INVALID_DATA;}
        catch(...){rc=ERROR_INVALID_DATA;}
        InterlockedExchange(slot+1,static_cast<LONG>(rc));
        engine_checked(SetEvent(done.h));
    }
}
