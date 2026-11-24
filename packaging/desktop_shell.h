#pragma once
#include <exdisp.h>
#include <shldisp.h>
#include <shlguid.h>
#include <wrl/client.h>
#undef ShellExecute  // IShellDispatch2 uses the unsuffixed automation method.

// Ask the interactive user's Explorer to start the ordinary FLURUX window.
inline HRESULT open_user_window(const wchar_t* launcher, const wchar_t* tab) {
    using Microsoft::WRL::ComPtr;
    HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(hr))return hr;
    struct Apartment { ~Apartment(){CoUninitialize();} } apartment;
    VARIANT loc{},empty{}; loc.vt=VT_I4; loc.lVal=CSIDL_DESKTOP;
    long hwnd=0;
    ComPtr<IShellWindows> windows;
    ComPtr<IDispatch> desktop,background,application;
    ComPtr<IServiceProvider> provider;
    ComPtr<IShellBrowser> browser;
    ComPtr<IShellView> view;
    ComPtr<IShellFolderViewDual> folder;
    ComPtr<IShellDispatch2> shell;
    if(FAILED(hr=CoCreateInstance(CLSID_ShellWindows,nullptr,CLSCTX_LOCAL_SERVER,IID_PPV_ARGS(windows.GetAddressOf()))) ||
       (hr=windows->FindWindowSW(&loc,&empty,SWC_DESKTOP,&hwnd,SWFO_NEEDDISPATCH,desktop.GetAddressOf()))!=S_OK ||
       FAILED(hr=desktop.As(&provider)) ||
       FAILED(hr=provider->QueryService(SID_STopLevelBrowser,IID_PPV_ARGS(browser.GetAddressOf()))) ||
       FAILED(hr=browser->QueryActiveShellView(view.GetAddressOf())) ||
       FAILED(hr=view->GetItemObject(SVGIO_BACKGROUND,IID_PPV_ARGS(background.GetAddressOf()))) ||
       FAILED(hr=background.As(&folder)) ||
       FAILED(hr=folder->get_Application(application.GetAddressOf())) ||
       FAILED(hr=application.As(&shell)))return FAILED(hr)?hr:E_FAIL;
    const auto args=std::wstring(L"/open ")+tab;
    VARIANT arguments{};arguments.vt=VT_BSTR;arguments.bstrVal=SysAllocString(args.c_str());
    BSTR file=SysAllocString(launcher);
    hr=file && arguments.bstrVal?shell->ShellExecute(file,arguments,empty,empty,empty):E_OUTOFMEMORY;
    SysFreeString(file);VariantClear(&arguments);
    return hr;
}
