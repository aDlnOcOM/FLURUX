#pragma once

static fs::path known_folder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &raw))) throw std::runtime_error("known folder");
    fs::path folder(raw);
    CoTaskMemFree(raw);
    return folder;
}

static bool valid_folder(const fs::path& folder) {
    const auto value = folder.native();
    if (value.size() < 4 || value.size() > FLURUX_MAX_FOLDER || !iswalpha(value[0]) || value[1] != L':' ||
        value[2] != L'\\' || value.find_first_of(L"\"*/<>?|", 3) != std::wstring::npos ||
        value.find(L':', 2) != std::wstring::npos || GetDriveTypeW(folder.root_path().c_str()) != DRIVE_FIXED) return false;
    fs::path current = folder.root_path();
    for (const auto& part : folder.relative_path()) {
        const auto name = part.native();
        if (name.empty() || name.back() == L'.' || name.back() == L' ' ||
            std::any_of(name.begin(), name.end(), [](wchar_t c){return c < 32;})) return false;
        wchar_t device[256]{};
        if (QueryDosDeviceW(part.stem().c_str(), device, ARRAYSIZE(device))) return false;
        current /= part;
        DWORD attr = GetFileAttributesW(current.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            auto error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return false;
        } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY) || (attr & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    }
    std::error_code error;
    if (!fs::exists(folder, error)) return !error;
    if (fs::is_empty(folder, error)) return !error;
    if (error || _wcsicmp(folder.c_str(), (known_folder(FOLDERID_ProgramFilesX64) / L"FLURUX").c_str())) return false;
    // Uninstall leaves manually added engines and administrator profiles in place.
    for (const auto& item : fs::directory_iterator(folder)) {
        const auto name=item.path().filename().native();
        if (name!=L"Security" && name!=L"engines" && name!=L"AdminData") return false;
        const auto attributes=GetFileAttributesW(item.path().c_str());
        if (attributes==INVALID_FILE_ATTRIBUTES || !(attributes&FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    }
    return true;
}
