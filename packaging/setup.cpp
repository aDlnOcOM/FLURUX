#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <filesystem>
#include <string>
#include <array>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace fs = std::filesystem;
static const wchar_t* product=L"{670D8AC3-5471-5723-97EF-D5CF18A9614E}";
#include "setup_ui.h"

struct File {
    HANDLE value=INVALID_HANDLE_VALUE;
    ~File(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
struct Package {
    const BYTE* bytes;
    DWORD length;
    Package(){
        HRSRC src=FindResourceW(nullptr,MAKEINTRESOURCEW(201),RT_RCDATA);
        HGLOBAL loaded=src?LoadResource(nullptr,src):nullptr;
        bytes=loaded?static_cast<const BYTE*>(LockResource(loaded)):nullptr;
        length=src?SizeofResource(nullptr,src):0;
        if(!bytes || !length)throw std::runtime_error("resource");
    }
    void save(const fs::path& dest) const {
        File file{CreateFileW(dest.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr)};
        DWORD written=0;
        if(file.value==INVALID_HANDLE_VALUE || !WriteFile(file.value,bytes,length,&written,nullptr)
           || written!=length || !FlushFileBuffers(file.value))throw std::runtime_error("write");
    }
    void verify(HANDLE file) const {
        LARGE_INTEGER actual{};
        if(!GetFileSizeEx(file,&actual) || actual.QuadPart!=length)throw std::runtime_error("size");
        std::array<BYTE,65536> buffer{};
        for(DWORD offset=0;offset<length;){
            DWORD n=0,request=std::min<DWORD>(static_cast<DWORD>(buffer.size()),length-offset);
            if(!ReadFile(file,buffer.data(),request,&n,nullptr) || n!=request ||
               std::memcmp(buffer.data(),bytes+offset,n))throw std::runtime_error("verify");
            offset+=n;
        }
    }
};
struct Staging {
    fs::path folder,msi;
    Staging(){
        GUID id{};wchar_t name[40]{},temp[32768]{};
        DWORD size=GetTempPathW(ARRAYSIZE(temp),temp);
        if(!size || size>=ARRAYSIZE(temp) || FAILED(CoCreateGuid(&id)) ||
           !StringFromGUID2(id,name,ARRAYSIZE(name)))throw std::runtime_error("staging");
        folder=fs::path(temp)/(std::wstring(L"FLURUX-")+name);
        if(!CreateDirectoryW(folder.c_str(),nullptr))throw std::runtime_error("staging");
        msi=folder/L"FLURUX-Desktop-x64.msi";
    }
    ~Staging(){DeleteFileW(msi.c_str());RemoveDirectoryW(folder.c_str());}
};
bool elevated(){
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return true;
    TOKEN_ELEVATION status{};DWORD size=0;
    BOOL ok=GetTokenInformation(token,TokenElevation,&status,sizeof(status),&size);
    CloseHandle(token);return !ok || status.TokenIsElevated;
}
void open_app(){
    const auto app=registered_folder()/L"FLURUX.exe";
    if(elevated() || reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr,L"open",app.c_str(),nullptr,app.parent_path().c_str(),SW_SHOWNORMAL))<=32){
        MessageBoxW(nullptr,L"FLURUX установлен. Откройте его через меню «Пуск».",L"FLURUX",MB_OK|MB_ICONINFORMATION);
    }
}
static void refresh_shortcuts(bool removed) {
    for (const auto* id : {&FOLDERID_CommonPrograms, &FOLDERID_PublicDesktop}) {
        const auto folder = known_folder(*id);
        const auto link = folder / L"FLURUX.lnk";
        SHChangeNotify(removed ? SHCNE_DELETE : SHCNE_UPDATEITEM, SHCNF_PATHW, link.c_str(), nullptr);
        SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSH, folder.c_str(), nullptr);
    }
}

static bool shortcuts_ready() {
    const auto expected=registered_folder()/L"FLURUX.exe";
    for (const auto* id : {&FOLDERID_CommonPrograms, &FOLDERID_PublicDesktop}) {
        Microsoft::WRL::ComPtr<IShellLinkW> link;
        Microsoft::WRL::ComPtr<IPersistFile> file;
        wchar_t path[32768]{};
        if (FAILED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(link.GetAddressOf()))) ||
            FAILED(link.As(&file)) || FAILED(file->Load((known_folder(*id)/L"FLURUX.lnk").c_str(),STGM_READ)) ||
            FAILED(link->GetPath(path,ARRAYSIZE(path),nullptr,SLGP_RAWPATH))) return false;
        std::error_code error;
        if(!fs::equivalent(expected,fs::path(path),error) || error)return false;
    }
    return true;
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    try{
        Package package;
        int argc=0;auto args=CommandLineToArgvW(GetCommandLineW(),&argc);
        if(!args)return ERROR_INVALID_PARAMETER;
        if(argc==3 && std::wstring(args[1])==L"/extract"){
            fs::path output(args[2]);LocalFree(args);package.save(output);return 0;
        }
        LocalFree(args);if(argc!=1)return ERROR_INVALID_PARAMETER;
        const HRESULT com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
        if (FAILED(com)) return ERROR_INSTALL_FAILURE;
        struct Apartment { ~Apartment(){CoUninitialize();} } apartment;
        wchar_t version[64]{}; DWORD capacity=ARRAYSIZE(version);
        UINT query=MsiGetProductInfoExW(product,nullptr,MSIINSTALLCONTEXT_MACHINE,
                                       INSTALLPROPERTY_VERSIONSTRING,version,&capacity);
        if(query!=ERROR_SUCCESS && query!=ERROR_UNKNOWN_PRODUCT) throw std::runtime_error("product");
        const bool installed=query==ERROR_SUCCESS;
        SetupChoice choice{registered_folder(),version};
        if(installed){
            unsigned major=0,minor=0,patch=0;
            choice.newer=swscanf_s(version,L"%u.%u.%u",&major,&minor,&patch)!=3 ||
                         major>0 || minor>3 || (minor==3 && patch>3);
            choice.older=!choice.newer && choice.version!=L"0.3.3";
        }
        auto action=DialogBoxParamW(GetModuleHandleW(nullptr),
            MAKEINTRESOURCEW(installed?IDD_MAINTAIN:IDD_INSTALL),nullptr,setup_dialog,
            reinterpret_cast<LPARAM>(&choice));
        if(action==-1)throw std::runtime_error("dialog");
        if(action!=IDOK && action!=IDC_REMOVE)return ERROR_INSTALL_USEREXIT;
        const bool remove=action==IDC_REMOVE;
        MsiSetInternalUI(INSTALLUILEVEL_BASIC,nullptr);
        if(remove){
            UINT rc=MsiConfigureProductExW(product,INSTALLLEVEL_DEFAULT,INSTALLSTATE_ABSENT,L"REBOOT=ReallySuppress");
            if(rc==ERROR_SUCCESS || rc==ERROR_SUCCESS_REBOOT_REQUIRED){
                refresh_shortcuts(true);
                MessageBoxW(nullptr,rc==ERROR_SUCCESS?L"FLURUX удалён.":L"Для завершения удаления перезагрузите Windows.",L"FLURUX",MB_OK);
                return rc;
            }
            if(rc==ERROR_INSTALL_USEREXIT)return rc;
            if(choice.version!=L"0.3.3" || (rc!=ERROR_INSTALL_SOURCE_ABSENT && rc!=ERROR_BAD_CONFIGURATION)){
                auto message=L"Не удалось удалить FLURUX. Код Windows Installer: "+std::to_wstring(rc);
                MessageBoxW(nullptr,message.c_str(),L"FLURUX",MB_ICONERROR);return rc;
            }
        }
        Staging temp;
        // Pin the staging directory as well as the payload while MSI opens its source by name.
        File directory{CreateFileW(temp.folder.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
                                   nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
        BY_HANDLE_FILE_INFORMATION info{};
        if(directory.value==INVALID_HANDLE_VALUE || !GetFileInformationByHandle(directory.value,&info) ||
           (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("directory");
        package.save(temp.msi);
        // Keep the verified filename locked for reading through Windows Installer.
        File lock{CreateFileW(temp.msi.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
        if(lock.value==INVALID_HANDLE_VALUE)throw std::runtime_error("lock");
        package.verify(lock.value);
        std::wstring options=L"REBOOT=ReallySuppress";
        if(remove) options+=L" REMOVE=ALL";
        else {
            options+=L" INSTALLDIR=\""+choice.folder.native()+L"\"";
            if(installed) options+=L" REINSTALL=ALL REINSTALLMODE=vamus";
        }
        auto rc=MsiInstallProductW(temp.msi.c_str(),options.c_str());
        if(rc==ERROR_SUCCESS){
            refresh_shortcuts(remove);
            if(remove)MessageBoxW(nullptr,L"FLURUX удалён.",L"FLURUX",MB_OK);
            else {
                if(!shortcuts_ready())MessageBoxW(nullptr,L"Проверьте ярлыки в меню «Пуск» и на рабочем столе. Если ярлык отсутствует, откройте этот установщик и нажмите «Восстановить».",L"Ярлыки FLURUX",MB_ICONINFORMATION);
                open_app();
            }
        }
        else if(rc==ERROR_SUCCESS_REBOOT_REQUIRED){
            MessageBoxW(nullptr,L"Операция завершена. Перезагрузите Windows.",L"FLURUX",MB_OK);
        }else if(rc!=ERROR_INSTALL_USEREXIT){
            auto msg=L"Windows Installer не завершил установку. Код "+std::to_wstring(rc)+
                L". Закройте запущенный FLURUX и повторите попытку.";
            MessageBoxW(nullptr,msg.c_str(),L"FLURUX",MB_ICONERROR);
        }
        return rc;
    }catch(...){
        MessageBoxW(nullptr,L"Не удалось подготовить установочные файлы. Проверьте свободное место и повторите запуск.",
                    L"FLURUX",MB_ICONERROR);
        return ERROR_INSTALL_FAILURE;
    }
}
