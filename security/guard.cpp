// Build with MSVC x64. This broker has no configurable executable, script or command line.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <fwpmu.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>
#include <cwctype>
#include <iostream>
#include "hashes.h"

namespace fs=std::filesystem;
using std::wstring;
void require(bool ok, DWORD code=ERROR_INVALID_DATA) { if(!ok) throw code; }
void checked(DWORD result) { if(result) throw result; }

struct Handle {
    HANDLE h=nullptr;
    explicit Handle(HANDLE v=nullptr):h(v){}
    ~Handle(){ if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&)=delete;
};
fs::path installed() {
    PWSTR out=nullptr;
    require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFilesX64,0,nullptr,&out)));
    fs::path dir(out); CoTaskMemFree(out); return dir/L"FLURUX"/L"Security";
}
bool trusted_sid(PSID sid) {
    LPWSTR str=nullptr;
    require(ConvertSidToStringSidW(sid,&str)!=FALSE);
    wstring val(str); LocalFree(str);
    return val==L"S-1-5-18" || val==L"S-1-5-32-544" ||
        val==L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
}
void secure(const fs::path& path) {
    auto flags=GetFileAttributesW(path.c_str());
    require(flags!=INVALID_FILE_ATTRIBUTES && !(flags&FILE_ATTRIBUTE_REPARSE_POINT));
    PSECURITY_DESCRIPTOR descriptor=nullptr; PSID owner=nullptr; PACL acl=nullptr;
    checked(GetNamedSecurityInfoW(path.c_str(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&descriptor));
    bool good=acl && trusted_sid(owner);
    for(unsigned i=0;good && i<acl->AceCount;++i){
        void* opaque=nullptr; require(GetAce(acl,i,&opaque)!=FALSE);
        auto ace=static_cast<ACCESS_ALLOWED_ACE*>(opaque);
        if(ace->Header.AceFlags & INHERIT_ONLY_ACE) continue;
        if(ace->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
        if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE){good=false;break;}
        constexpr DWORD writes=GENERIC_ALL|GENERIC_WRITE|WRITE_DAC|WRITE_OWNER|DELETE|
            FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD;
        if((ace->Mask&writes) && !trusted_sid(&ace->SidStart)) good=false;
    }
    LocalFree(descriptor); require(good,ERROR_ACCESS_DENIED);
}
void installed_paths(const fs::path& dir) {
    secure(dir.parent_path().parent_path()); secure(dir.parent_path()); secure(dir);
    secure(dir/L"FluruxGuard.exe");
    wchar_t here[32768]{};
    require(GetModuleFileNameW(nullptr,here,32768)>0 && fs::equivalent(here,dir/L"FluruxGuard.exe"));
}
std::string sha(const fs::path& path){
    std::ifstream stream(path,std::ios::binary);require(stream.good());
    BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);
    require(BCryptCreateHash(algorithm,&hash,nullptr,0,nullptr,0,0)==0);
    std::array<char,65536> chunk{};
    while(stream){ stream.read(chunk.data(),chunk.size());
        require(BCryptHashData(hash,reinterpret_cast<PUCHAR>(chunk.data()),static_cast<ULONG>(stream.gcount()),0)==0); }
    require(stream.eof());
    unsigned char digest[32]{};require(BCryptFinishHash(hash,digest,sizeof(digest),0)==0);
    BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(algorithm,0);
    std::string result;for(auto c:digest){const char* hex="0123456789abcdef";result+=hex[c>>4];result+=hex[c&15];}
    return result;
}
void verify_engine(const fs::path& dir,bool check_acl){
    std::set<fs::path> expected{L"lua",L"files"};
    for(const auto& file:files){
        fs::path key=fs::path(file.first).make_preferred();
        expected.insert(key);require(sha(dir/key)==file.second,ERROR_CRC);
    }
    if(check_acl)secure(dir);
    for(auto const& item:fs::recursive_directory_iterator(dir)){
        require(expected.erase(item.path().lexically_relative(dir))==1);
        require(!(GetFileAttributesW(item.path().c_str())&FILE_ATTRIBUTE_REPARSE_POINT));
        if(check_acl)secure(item.path());
    }
    require(expected.empty());
}
bool domains_ok(const wstring& csv){
    if(csv.empty() || csv.size()>12000)return false;
    size_t domain=0,label=0;
    for(size_t i=0;i<=csv.size();++i){
        wchar_t c=i==csv.size()?L',':csv[i];
        if(c==L',' || c==L'.'){
            if(!label || label>63 || csv[i-1]==L'-')return false;
            label=0;
            if(c==L','){if(domain>253)return false;domain=0;}else ++domain;
        }else{
            if(!(c>=L'a' && c<=L'z') && !(c>=L'0' && c<=L'9') && !(c==L'-' && label))return false;
            ++label;++domain;
        }
    }
    return true;
}
#include "engine_setup.h"
struct Signals{
    Handle parent,stop,ready;
    Signals(const wstring& pid,const wstring& nonce){
        require(pid.size()>0 && pid.size()<=10 && pid.find_first_not_of(L"0123456789")==wstring::npos);
        require(nonce.size()==32 && nonce.find_first_not_of(L"0123456789abcdef")==wstring::npos);
        auto id=std::stoull(pid);require(id>0 && id<=MAXDWORD);
        parent.h=OpenProcess(SYNCHRONIZE,FALSE,static_cast<DWORD>(id));
        auto prefix=L"Local\\FLURUX-"+nonce;
        stop.h=OpenEventW(SYNCHRONIZE,FALSE,(prefix+L"-stop").c_str());
        ready.h=OpenEventW(EVENT_MODIFY_STATE,FALSE,(prefix+L"-ready").c_str());
        require(parent.h && stop.h && ready.h,ERROR_INVALID_HANDLE);
    }
};
int zapret(const fs::path& dir,Signals& signals,const wstring& strategy,const wstring& domains,
           const wstring& excluded,const wstring& tcp,const wstring& udp,const wstring& family){
    require(domains_ok(domains) && (strategy==L"split" || strategy==L"disorder" || strategy==L"quic" || strategy==L"disorder_quic"));
    require(family==L"both" || family==L"ipv4" || family==L"ipv6");
    bool quic=strategy==L"quic" || strategy==L"disorder_quic";
    require(valid_ports(tcp) && valid_ports(udp) && (excluded==L"-" || domains_ok(excluded)) && domains.size()+excluded.size()<=12001);
    Handle lock(engine_lock(dir.parent_path()));
    recover_engine(dir.parent_path());
    verify_engine(dir,true);
    auto exe=dir/L"winws2.exe";
    auto hosts=L" --hostlist-domains="+domains;
    if(excluded!=L"-")hosts+=L" --hostlist-exclude-domains="+excluded;
    wstring line=L"\""+exe.wstring()+L"\" --wf-tcp-out="+tcp+L" --lua-init=@lua/zapret-lib.lua --lua-init=@lua/zapret-antidpi.lua";
    if(family!=L"both")line+=L" --wf-l3="+family;
    if(quic)line+=L" --wf-udp-out="+udp+L" --blob=quic:@files/quic_initial_www_google_com.bin";
    line+=L" --filter-tcp="+tcp+L" --filter-l7=tls"+hosts+L" --out-range=-d10 --payload=tls_client_hello --lua-desync=";
    line+=((strategy==L"disorder" || strategy==L"disorder_quic")?L"multidisorder":L"multisplit");line+=L":pos=1,midsld";
    if(quic)line+=L" --new --filter-udp="+udp+L" --filter-l7=quic"+hosts+L" --out-range=-d10 --payload=quic_initial --lua-desync=fake:blob=quic:repeats=6";
    wchar_t win[MAX_PATH]{};require(GetWindowsDirectoryW(win,MAX_PATH)>0);
    // No user-controlled PATH, Lua paths, HOME or CYGWIN settings in the elevated engine.
    wstring env=L"PATH="+wstring(win)+L"\\System32";env.push_back(0);
    env+=L"SystemRoot="+wstring(win);env.push_back(0);env+=L"WINDIR="+wstring(win);env.push_back(0);env.push_back(0);
    Handle job(CreateJobObjectW(nullptr,nullptr));require(job.h!=nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE);
    STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);SIZE_T size=0;
    InitializeProcThreadAttributeList(nullptr,1,0,&size);
    std::vector<BYTE> buffer(size);si.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
    require(InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&size)!=FALSE);
    require(UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&job.h,sizeof(HANDLE),nullptr,nullptr)!=FALSE);
    PROCESS_INFORMATION pi{};
    BOOL started=CreateProcessW(exe.c_str(),line.data(),nullptr,nullptr,FALSE,
        CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,env.data(),dir.c_str(),&si.StartupInfo,&pi);
    auto error=GetLastError();DeleteProcThreadAttributeList(si.lpAttributeList);require(started!=FALSE,error);
    Handle process(pi.hProcess),thread(pi.hThread);HANDLE waits[]={signals.parent.h,signals.stop.h,process.h};
    DWORD wait=WaitForMultipleObjects(3,waits,FALSE,1200);
    if(wait==WAIT_TIMEOUT){require(SetEvent(signals.ready.h)!=FALSE);wait=WaitForMultipleObjects(3,waits,FALSE,INFINITE);}
    if(wait==WAIT_OBJECT_0+2){DWORD rc=0;GetExitCodeProcess(process.h,&rc);return rc?rc:1;}
    require(wait==WAIT_OBJECT_0 || wait==WAIT_OBJECT_0+1);return 0;
}
#include "benchmark.h"
#include "network_lock.h"
int wmain(int argc,wchar_t** argv){
    try{
        if(argc==2 && wstring(argv[1])==L"self-test"){
            require(domains_ok(L"example.org,xn--e1afmkfd.xn--p1ai") && !domains_ok(L"-bad") && !domains_ok(L"a,b.") && !domains_ok(L"a --x"));
            return 0;
        }
        if(argc==3 && wstring(argv[1])==L"verify-files"){verify_engine(fs::absolute(argv[2]),false);return 0;}
        auto dir=installed();installed_paths(dir);
        if(argc==2 && wstring(argv[1])==L"unlock"){unlock_network();return 0;}
        if(argc==3 && wstring(argv[1])==L"install-engine"){manage_engine(dir,argv[2],false);return 0;}
        if(argc==2 && wstring(argv[1])==L"remove-engine"){manage_engine(dir,L"",true);return 0;}
        require(argc>=4);Signals signals(argv[2],argv[3]);
        if(argc==6 && wstring(argv[1])==L"benchmark")return benchmark(dir/L"engine",signals,argv[3],argv[4],argv[5]);
        if(argc==10 && wstring(argv[1])==L"zapret")return zapret(dir/L"engine",signals,argv[4],argv[5],argv[6],argv[7],argv[8],argv[9]);
        if(argc==8 && wstring(argv[1])==L"lock"){network_lock(signals,argv[4],argv[5],argv[6],argv[7]);return 0;}
        return ERROR_INVALID_PARAMETER;
    }catch(const fs::filesystem_error& e){return e.code().value()?e.code().value():ERROR_INVALID_DATA;}
    catch(DWORD rc){return static_cast<int>(rc?rc:ERROR_INVALID_DATA);}
    catch(...){return ERROR_INVALID_DATA;}
}
