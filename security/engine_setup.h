#pragma once
#include <cstdint>
#include <cstring>

inline void engine_checked(BOOL ok){if(!ok)throw GetLastError();}

// Both mutation and launch hold this file exclusively. Windows releases it on process exit.
inline HANDLE engine_lock(const fs::path& security) {
    auto lock=CreateFileW((security/L"engine.lock").c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,
                          OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE,nullptr);
    require(lock!=INVALID_HANDLE_VALUE,GetLastError());
    return lock;
}

struct EngineSecurity {
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,FALSE};
    EngineSecurity(){
        engine_checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
            SDDL_REVISION_1,&descriptor,nullptr));
        attributes.lpSecurityDescriptor=descriptor;
    }
    ~EngineSecurity(){LocalFree(descriptor);}
};

// Refuse links and unrecognized names. A damaged or partial managed installation is repairable.
inline void check_layout(const fs::path& root){
    secure(root);
    std::set<fs::path> directories{L"files",L"lua"},members;
    for(const auto& file:files) members.insert(fs::path(file.first).make_preferred());
    for(const auto& item:fs::recursive_directory_iterator(root)){
        secure(item.path());
        auto key=item.path().lexically_relative(root);
        require(item.is_directory()?directories.count(key)==1:members.count(key)==1,ERROR_DIR_NOT_EMPTY);
    }
}
inline void discard_engine(const fs::path& path){
    if(!fs::exists(path))return;
    check_layout(path);
    for(const auto& item:files)fs::remove(path/item.first);
    fs::remove(path/L"lua");fs::remove(path/L"files");fs::remove(path);
}

struct MappedBundle {
    static constexpr DWORD capacity=8*1024*1024;
    Handle section;
    const BYTE* bytes;
    explicit MappedBundle(const wstring& nonce):
        section(OpenFileMappingW(FILE_MAP_READ,FALSE,(L"Local\\FLURUX-engine-"+nonce).c_str())),
        bytes(nullptr){
        require(section.h!=nullptr,GetLastError());
        bytes=static_cast<const BYTE*>(MapViewOfFile(section.h,FILE_MAP_READ,0,0,capacity));
        require(bytes!=nullptr,GetLastError());
    }
    ~MappedBundle(){if(bytes)UnmapViewOfFile(bytes);}
};

inline void write_stage(const fs::path& stage,const BYTE* bytes,DWORD capacity,EngineSecurity& security){
    engine_checked(CreateDirectoryW(stage.c_str(),&security.attributes));
    for(auto name:{L"lua",L"files"})
        engine_checked(CreateDirectoryW((stage/name).c_str(),&security.attributes));
    DWORD offset=0;
    for(const auto& file:files){
        DWORD length=0;
        require(capacity-offset>=sizeof(length));
        std::memcpy(&length,bytes+offset,sizeof(length));offset+=sizeof(length);
        require(length>0 && length<=capacity-offset);
        Handle output(CreateFileW((stage/file.first).c_str(),GENERIC_WRITE,0,&security.attributes,
                                  CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
        require(output.h!=INVALID_HANDLE_VALUE,GetLastError());
        DWORD written=0;
        require(WriteFile(output.h,bytes+offset,length,&written,nullptr)!=FALSE && written==length,ERROR_WRITE_FAULT);
        offset+=length;
    }
    // Verify the protected copies, independently of the caller and of the shared memory.
    verify_engine(stage,true);
}
inline void recover_engine(const fs::path& security){
    const auto live=security/L"engine",previous=security/L"engine.previous";
    if(fs::exists(previous)){
        if(fs::exists(live))discard_engine(previous);
        else {check_layout(previous);fs::rename(previous,live);}
    }
    discard_engine(security/L"engine.stage");
}
inline void manage_engine(const fs::path& security,const wstring& nonce,bool remove){
    Handle lock(engine_lock(security));
    recover_engine(security);
    const auto live=security/L"engine",stage=security/L"engine.stage",previous=security/L"engine.previous";
    if(fs::exists(live))check_layout(live);
    if(remove){
        if(fs::exists(live)){fs::rename(live,stage);discard_engine(stage);}
        return;
    }
    require(nonce.size()==32 && nonce.find_first_not_of(L"0123456789abcdef")==wstring::npos);
    MappedBundle data(nonce);
    EngineSecurity acl;
    try {
        write_stage(stage,data.bytes,MappedBundle::capacity,acl);
        if(fs::exists(live))fs::rename(live,previous);
        fs::rename(stage,live);
    } catch(...) {recover_engine(security);throw;}
    discard_engine(previous);
}
inline bool valid_ports(const wstring& text){
    if(text.empty()||text.size()>95)return false;
    unsigned number=0,digits=0;
    for(size_t i=0;i<=text.size();++i){
        auto c=i==text.size()?L',':text[i];
        if(c==L','){if(!digits||!number||number>65535)return false;digits=0;number=0;}
        else {if(c<L'0'||c>L'9'||++digits>5)return false;number=number*10+c-L'0';}
    }
    return true;
}
