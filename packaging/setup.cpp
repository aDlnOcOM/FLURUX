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
    PWSTR folder=nullptr;
    if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFilesX64,0,nullptr,&folder)))return;
    fs::path app=fs::path(folder)/L"FLURUX"/L"FLURUX.exe";
    CoTaskMemFree(folder);
    if(elevated() || reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr,L"open",app.c_str(),nullptr,app.parent_path().c_str(),SW_SHOWNORMAL))<=32){
        MessageBoxW(nullptr,L"FLURUX установлен. Откройте его через меню «Пуск».",L"FLURUX",MB_OK|MB_ICONINFORMATION);
    }
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
        wchar_t version[64]{};DWORD capacity=ARRAYSIZE(version);
        bool installed=MsiGetProductInfoW(product,INSTALLPROPERTY_VERSIONSTRING,version,&capacity)==ERROR_SUCCESS;
        if(installed){
            unsigned major=0,minor=0,patch=0;
            if(swscanf_s(version,L"%u.%u.%u",&major,&minor,&patch)!=3 ||
               major>0 || minor>3 || (minor==3 && patch>2)){
                MessageBoxW(nullptr,L"Уже установлена более новая версия FLURUX.",L"FLURUX",MB_ICONINFORMATION);
                return ERROR_PRODUCT_VERSION;
            }
        }
        if(MessageBoxW(nullptr,installed?
            L"Обновить или восстановить FLURUX 0.3.2 и открыть приложение?":
            L"Установить FLURUX 0.3.2 и открыть приложение?\n\nВсё необходимое для запуска входит в комплект. Ярлык появится в меню «Пуск».",
            L"Установка FLURUX",MB_OKCANCEL|MB_ICONINFORMATION)!=IDOK)return ERROR_INSTALL_USEREXIT;
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
        MsiSetInternalUI(INSTALLUILEVEL_BASIC,nullptr);
        auto rc=MsiInstallProductW(temp.msi.c_str(),installed?
            L"REINSTALL=ALL REINSTALLMODE=vomus REBOOT=ReallySuppress":L"REBOOT=ReallySuppress");
        if(rc==ERROR_SUCCESS)open_app();
        else if(rc==ERROR_SUCCESS_REBOOT_REQUIRED){
            MessageBoxW(nullptr,L"Установка завершена. Перезагрузите Windows и откройте FLURUX через «Пуск».",L"FLURUX",MB_OK);
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
