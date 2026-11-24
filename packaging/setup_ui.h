#pragma once
#include <shobjidl.h>
#include <wrl/client.h>
#include "setup_ids.h"

struct SetupChoice {
    fs::path folder;
    std::wstring version;
    bool older = false;
    bool newer = false;
};

#include "install_folder.h"

static fs::path registered_folder() {
    wchar_t text[32768]{};
    DWORD length = ARRAYSIZE(text);
    const auto state = MsiGetComponentPathExW(product, L"{33120448-451B-5A7A-8A5E-E610FEAC65FD}",
        nullptr, MSIINSTALLCONTEXT_MACHINE, text, &length);
    if (state == INSTALLSTATE_LOCAL && text[0]) return fs::path(text).parent_path();
    length = ARRAYSIZE(text);
    if (MsiGetProductInfoExW(product, nullptr, MSIINSTALLCONTEXT_MACHINE,
        INSTALLPROPERTY_INSTALLLOCATION, text, &length) == ERROR_SUCCESS && text[0]) return fs::path(text);
    return known_folder(FOLDERID_ProgramFilesX64) / L"FLURUX";  // Versions without InstallLocation.
}

static void browse(HWND owner) {
    Microsoft::WRL::ComPtr<IFileOpenDialog> dialog;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(dialog.GetAddressOf())))) return;
    DWORD flags{};
    dialog->GetOptions(&flags);
    dialog->SetOptions(flags | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dialog->SetTitle(L"Выберите родительскую папку для FLURUX");
    if (FAILED(dialog->Show(owner))) return;
    Microsoft::WRL::ComPtr<IShellItem> selected;
    PWSTR raw = nullptr;
    if (SUCCEEDED(dialog->GetResult(selected.GetAddressOf())) &&
        SUCCEEDED(selected->GetDisplayName(SIGDN_FILESYSPATH, &raw))) {
        fs::path path(raw);
        CoTaskMemFree(raw);
        if (_wcsicmp(path.filename().c_str(), L"FLURUX") != 0) path /= L"FLURUX";
        SetDlgItemTextW(owner, IDC_FOLDER, path.c_str());
    }
}

static INT_PTR CALLBACK setup_dialog(HWND window, UINT msg, WPARAM wparam, LPARAM lparam) {
    auto choice = reinterpret_cast<SetupChoice*>(GetWindowLongPtrW(window, DWLP_USER));
    try {
        if (msg == WM_INITDIALOG) {
            choice = reinterpret_cast<SetupChoice*>(lparam);
            SetWindowLongPtrW(window, DWLP_USER, lparam);
            SetDlgItemTextW(window, IDC_FOLDER, choice->folder.c_str());
            if (!choice->version.empty()) {
                SetDlgItemTextW(window, IDC_VERSION, (L"Установлена версия " + choice->version).c_str());
                if (choice->older) SetDlgItemTextW(window, IDOK, L"Обновить и восстановить");
                if (choice->newer) EnableWindow(GetDlgItem(window, IDOK), FALSE);
            }
            return TRUE;
        }
        if (msg == WM_CLOSE) { EndDialog(window, IDCANCEL); return TRUE; }
        if (msg != WM_COMMAND || !choice) return FALSE;
        switch (LOWORD(wparam)) {
        case IDCANCEL: EndDialog(window, IDCANCEL); return TRUE;
        case IDC_BROWSE: browse(window); return TRUE;
        case IDC_REMOVE:
            if (MessageBoxW(window, L"Удалить FLURUX и оба ярлыка? Настройки и профили останутся на диске. Если включена блокировка сети, сначала снимите её в разделе «Каскады».",
                L"Удаление FLURUX", MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) == IDYES)
                EndDialog(window, IDC_REMOVE);
            return TRUE;
        case IDOK:
            if (choice->newer) return TRUE;
            if (choice->version.empty()) {
                wchar_t text[32768]{};
                GetDlgItemTextW(window, IDC_FOLDER, text, ARRAYSIZE(text));
                fs::path folder(text);
                if (folder.has_relative_path() && folder.filename().empty()) folder = folder.parent_path();
                if (!valid_folder(folder)) {
                    auto hint = L"Укажите новую или пустую папку на локальном диске, без ссылок. Максимальная длина пути — "+std::to_wstring(FLURUX_MAX_FOLDER)+L" символов.";
                    MessageBoxW(window, hint.c_str(),
                        L"Папка установки", MB_OK | MB_ICONINFORMATION);
                    return TRUE;
                }
                choice->folder = folder;
            }
            EndDialog(window, IDOK);
            return TRUE;
        }
    } catch (...) {
        MessageBoxW(window, L"Не удалось открыть папку. Введите полный путь вручную.", L"FLURUX", MB_OK);
        return TRUE;
    }
    return FALSE;
}
