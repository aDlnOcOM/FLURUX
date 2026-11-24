#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <string>
#include "admin_location.h"
#include <shellapi.h>
#include "desktop_shell.h"

// Keeping the interpreter as a separate, isolated process also supports the
// existing MASQUE worker protocol (pythonw -I script.py client -).
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    wchar_t module[32768]{};
    if (!GetModuleFileNameW(nullptr, module, ARRAYSIZE(module))) return 1;
    const auto root = std::filesystem::path(module).parent_path();
    const auto runtime = root / L"runtime";
    int argc=0;
    auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!argv)return ERROR_INVALID_PARAMETER;
    std::wstring operation=argc==3?argv[1]:L"", tab=argc==3?argv[2]:L"";
    LocalFree(argv);
    if(argc!=1 && (argc!=3 || (operation!=L"/ordinary" && operation!=L"/open") ||
        (tab!=L"connection" && tab!=L"settings" && tab!=L"mesh")))return ERROR_INVALID_PARAMETER;
    if(operation==L"/ordinary" && IsUserAnAdmin()){
        if(FAILED(open_user_window(module,tab.c_str()))){
            MessageBoxW(nullptr,L"Откройте FLURUX через «Пуск» в обычном сеансе Windows.",L"FLURUX",MB_ICONINFORMATION);
            return ERROR_NO_LOGON_SERVERS;
        }
        return 0;
    }
    if(operation==L"/open" && IsUserAnAdmin()){
        MessageBoxW(nullptr,L"Проводник запущен с правами администратора. Для этого раздела откройте FLURUX из обычной учётной записи.",L"FLURUX",MB_ICONINFORMATION);
        return ERROR_ACCESS_DENIED;
    }
    if (IsUserAnAdmin()) {
        try {
            if (!flurux::admin_tree(root)) throw std::runtime_error("permissions");
        } catch (...) {
            MessageBoxW(nullptr, L"Для системного VPN требуется каталог установки с правами записи только у администраторов. Откройте FLURUX с обычными правами или восстановите установку в защищённой папке.", L"FLURUX", MB_ICONERROR);
            return ERROR_ACCESS_DENIED;
        }
    }
    const auto python = runtime / L"pythonw.exe";
    const auto entry = root / L"run.pyw";
    SetEnvironmentVariableW(L"TCL_LIBRARY", (runtime / L"tcl/tcl8.6").c_str());
    SetEnvironmentVariableW(L"TK_LIBRARY", (runtime / L"tcl/tk8.6").c_str());
    SetEnvironmentVariableW(L"TCLLIBPATH", nullptr);
    std::wstring args = L"\"" + python.wstring() + L"\" -I -B \"" + entry.wstring() + L"\"";
    if(!tab.empty())args+=L" --tab "+tab;
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(python.c_str(), args.data(), nullptr, nullptr, FALSE,
                        0, nullptr, root.c_str(), &startup, &child)) {
        MessageBoxW(nullptr, L"Не удалось открыть FLURUX. Повторите установку из файла Setup.exe.",
                    L"FLURUX", MB_OK | MB_ICONERROR);
        return 1;
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return 0;
}
