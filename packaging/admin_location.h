#pragma once
#include <aclapi.h>
#include <msi.h>
#include <sddl.h>
#include <shlobj.h>

namespace flurux {
namespace fs = std::filesystem;

// A directory above the installation may permit creating siblings without
// permitting removal of the protected FLURUX directory itself.
inline bool trustworthy(const fs::path& path, bool ancestor) {
    DWORD flags = GetFileAttributesW(path.c_str());
    if (flags == INVALID_FILE_ATTRIBUTES || (flags & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
    auto trusted = [](PSID sid) {
        if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) return true;
        PWSTR text = nullptr;
        if (!ConvertSidToStringSidW(sid, &text)) return false;
        bool installer = wcscmp(text, L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464") == 0;
        LocalFree(text);
        return installer;
    };
    DWORD mask = GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD |
                 FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
    if (!ancestor) mask |= FILE_WRITE_DATA | FILE_APPEND_DATA;
    bool safe = owner && acl && trusted(owner);
    for (DWORD i=0; safe && i<acl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(acl,i,&raw)) {safe=false; break;}
        auto ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if (ace->Header.AceFlags & INHERIT_ONLY_ACE || ace->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
        safe=ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE && (!(ace->Mask & mask) || trusted(&ace->SidStart));
    }
    LocalFree(descriptor);
    return safe;
}

inline bool admin_tree(const fs::path& root) {
    wchar_t launcher[32768]{}; DWORD n=ARRAYSIZE(launcher);
    if (MsiGetComponentPathExW(L"{670D8AC3-5471-5723-97EF-D5CF18A9614E}",
        L"{33120448-451B-5A7A-8A5E-E610FEAC65FD}",nullptr,MSIINSTALLCONTEXT_MACHINE,launcher,&n)!=INSTALLSTATE_LOCAL ||
        _wcsicmp(fs::path(launcher).parent_path().c_str(),root.c_str())) return false;
    for (auto p=root;;p=p.parent_path()) {
        if(!trustworthy(p,p!=root))return false;
        if(p==p.root_path())break;
    }
    for(auto name:{L"FLURUX.exe",L"run.pyw",L"src",L"runtime"}){
        auto p=root/name;
        if(!trustworthy(p,false))return false;
        if(fs::is_directory(p)){
            for(const auto& item:fs::recursive_directory_iterator(p)){
                if(!trustworthy(item.path(),false))return false;
            }
        }
    }
    return true;
}
}
