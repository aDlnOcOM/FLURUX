#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <string>

// Keeping the interpreter as a separate, isolated process also supports the
// existing MASQUE worker protocol (pythonw -I script.py client -).
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    wchar_t module[32768]{};
    if (!GetModuleFileNameW(nullptr, module, ARRAYSIZE(module))) return 1;
    const auto root = std::filesystem::path(module).parent_path();
    const auto runtime = root / L"runtime";
    const auto python = runtime / L"pythonw.exe";
    const auto entry = root / L"run.pyw";
    SetEnvironmentVariableW(L"TCL_LIBRARY", (runtime / L"tcl/tcl8.6").c_str());
    SetEnvironmentVariableW(L"TK_LIBRARY", (runtime / L"tcl/tk8.6").c_str());
    SetEnvironmentVariableW(L"TCLLIBPATH", nullptr);
    std::wstring args = L"\"" + python.wstring() + L"\" -I -B \"" + entry.wstring() + L"\"";
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
