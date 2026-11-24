#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msiquery.h>
#include <shlobj.h>
#include <algorithm>
#include <filesystem>
#include <string>
#include <stdexcept>

namespace fs = std::filesystem;
#include "install_folder.h"

// Validate in the MSI execute sequence as well as in the bootstrapper, before
// Windows Installer can create the application directory or change its ACL.
extern "C" __declspec(dllexport) UINT __stdcall CheckInstallFolder(MSIHANDLE session) {
    try {
        wchar_t buffer[32768]{};
        DWORD length=ARRAYSIZE(buffer);
        if(MsiGetTargetPathW(session,L"INSTALLDIR",buffer,&length)==ERROR_SUCCESS){
            fs::path folder(buffer);
            if(folder.has_relative_path() && folder.filename().empty()) folder=folder.parent_path();
            if(valid_folder(folder))return ERROR_SUCCESS;
        }
    } catch (...) {}
    PMSIHANDLE message=MsiCreateRecord(0);
    MsiRecordSetStringW(message,0,L"Выберите новую или пустую папку FLURUX на локальном диске без ссылок.");
    MsiProcessMessage(session,INSTALLMESSAGE_ERROR,message);
    return ERROR_INSTALL_FAILURE;
}
