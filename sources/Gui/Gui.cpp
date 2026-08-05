#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/imgui_internal.h"

#include <d3d11.h>
#include <dwmapi.h>
#include <filesystem>
#include <algorithm>
#include <vector>

#include "Gui.h"

#include "sources/Utils/Utils.h"

#include "sources/Core/DLLInjection.h"
#include "resource.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif
#ifndef DWMWA_TEXT_COLOR
#define DWMWA_TEXT_COLOR 36
#endif

// DirectX объекты
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;


// Forward declarations
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void SetupMinimalDarkStyle()
{
    ImGuiStyle& style = ImGui::GetStyle();

    style.WindowRounding    = 10.0f;
    style.ChildRounding     = 8.0f;
    style.FrameRounding     = 6.0f;
    style.PopupRounding     = 8.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 6.0f;

    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.FrameBorderSize   = 0.0f;

    style.WindowPadding     = ImVec2(16.0f, 16.0f);
    style.FramePadding      = ImVec2(10.0f, 6.0f);
    style.ItemSpacing       = ImVec2(10.0f, 10.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 6.0f);

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text]                  = ImVec4(0.93f, 0.94f, 0.96f, 1.00f);
    colors[ImGuiCol_TextDisabled]          = ImVec4(0.48f, 0.50f, 0.56f, 1.00f);
    colors[ImGuiCol_WindowBg]              = ImVec4(0.08f, 0.09f, 0.11f, 1.00f); // #14171C
    colors[ImGuiCol_ChildBg]               = ImVec4(0.12f, 0.13f, 0.16f, 1.00f); // #1F2129
    colors[ImGuiCol_PopupBg]               = ImVec4(0.12f, 0.13f, 0.16f, 0.96f);
    colors[ImGuiCol_Border]                = ImVec4(0.20f, 0.22f, 0.28f, 0.40f);
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]               = ImVec4(0.15f, 0.16f, 0.20f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.20f, 0.22f, 0.28f, 1.00f);
    colors[ImGuiCol_FrameBgActive]         = ImVec4(0.24f, 0.26f, 0.33f, 1.00f);
    colors[ImGuiCol_TitleBg]               = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);
    colors[ImGuiCol_TitleBgActive]         = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);
    colors[ImGuiCol_MenuBarBg]             = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]           = ImVec4(0.08f, 0.09f, 0.11f, 0.50f);
    colors[ImGuiCol_ScrollbarGrab]         = ImVec4(0.20f, 0.22f, 0.28f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.30f, 0.33f, 0.42f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.40f, 0.44f, 0.55f, 1.00f);
    colors[ImGuiCol_CheckMark]             = ImVec4(0.39f, 0.40f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrab]            = ImVec4(0.39f, 0.40f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]      = ImVec4(0.49f, 0.50f, 1.00f, 1.00f);
    colors[ImGuiCol_Button]                = ImVec4(0.16f, 0.18f, 0.24f, 1.00f);
    colors[ImGuiCol_ButtonHovered]         = ImVec4(0.22f, 0.25f, 0.34f, 1.00f);
    colors[ImGuiCol_ButtonActive]          = ImVec4(0.28f, 0.31f, 0.42f, 1.00f);
    colors[ImGuiCol_Header]                = ImVec4(0.16f, 0.18f, 0.24f, 1.00f);
    colors[ImGuiCol_HeaderHovered]         = ImVec4(0.22f, 0.25f, 0.34f, 1.00f);
    colors[ImGuiCol_HeaderActive]          = ImVec4(0.28f, 0.31f, 0.42f, 1.00f);
    colors[ImGuiCol_Separator]             = ImVec4(0.20f, 0.22f, 0.28f, 0.40f);
    colors[ImGuiCol_SeparatorHovered]      = ImVec4(0.39f, 0.40f, 0.95f, 0.78f);
    colors[ImGuiCol_SeparatorActive]       = ImVec4(0.39f, 0.40f, 0.95f, 1.00f);
    colors[ImGuiCol_ResizeGrip]            = ImVec4(0.20f, 0.22f, 0.28f, 0.20f);
    colors[ImGuiCol_ResizeGripHovered]     = ImVec4(0.39f, 0.40f, 0.95f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]      = ImVec4(0.39f, 0.40f, 0.95f, 0.95f);
    colors[ImGuiCol_TextSelectedBg]        = ImVec4(0.39f, 0.40f, 0.95f, 0.35f);
    colors[ImGuiCol_NavHighlight]          = ImVec4(0.39f, 0.40f, 0.95f, 1.00f);
}

void window()
{
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"PE Informer", nullptr };

    wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wc.hIconSm = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"INJECTOR", WS_OVERLAPPEDWINDOW ^ WS_MAXIMIZEBOX, 100, 100, width, heigth, nullptr, nullptr, wc.hInstance, nullptr);

    BOOL USE_DARK_MODE = TRUE;
    COLORREF BackgroundColor = RGB(20, 23, 28);
    COLORREF TextColor = RGB(237, 240, 245);
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &USE_DARK_MODE, sizeof(USE_DARK_MODE));
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &BackgroundColor, sizeof(BackgroundColor));
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &TextColor, sizeof(TextColor));

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D(); 
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Настройка ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
    
    SetupMinimalDarkStyle();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImFont* fontMain = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 15.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    if (!fontMain) fontMain = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", 15.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(fontMain != NULL);

    ImFont* fontTitle = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", 18.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    if (!fontTitle) fontTitle = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arialbd.ttf", 18.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(fontTitle != NULL);

    ImFont* fontSmall = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 12.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    if (!fontSmall) fontSmall = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", 12.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(fontSmall != NULL);

    ImVec4 clear_color = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);

    std::wstring directoryPathForDll;
    std::wstring directoryPathForExe;
    static std::string outputFalls;
    static int onClicedButtonForInjectDll = 0;

    static std::vector<ProcessInfo> processList;
    static int selectedProcessIdx = -1;
    static char processSearchFilter[128] = "";
    static DWORD selectedPid = 0;
    static std::string selectedExeName = "";

    if (processList.empty())
    {
        processList = getRunningProcesses(g_pd3dDevice);
    }

    while (windowExit) 
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) windowExit = false;
        }
        if (!windowExit) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin("DLL INJECTOR", &windowExit, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBringToFrontOnFocus);

        ImGui::PushFont(fontMain);

        ImGui::BeginChild("DllCard", ImVec2(0, 75), true, ImGuiWindowFlags_NoScrollbar);
        {
            ImGui::PushFont(fontSmall);
            ImGui::TextColored(ImVec4(0.55f, 0.58f, 0.65f, 1.00f), "ФАЙЛ DLL");
            ImGui::PopFont();
            
            std::string dllFilename = std::filesystem::path(wstringToUtf8(directoryPathForDll)).filename().string();
            
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 90.0f);
            if (dllFilename.empty())
            {
                ImGui::TextColored(ImVec4(0.48f, 0.50f, 0.56f, 1.00f), "Файл не выбран");
            }
            else
            {
                if (directoryPathForDll.ends_with(L".dll"))
                {
                    ImGui::TextColored(ImVec4(0.39f, 0.40f, 0.95f, 1.00f), "[DLL]");
                    ImGui::SameLine();
                    ImGui::TextUnformatted(dllFilename.c_str());
                }
                else
                    ImGui::TextColored(ImVec4(0.48f, 0.50f, 0.56f, 1.00f), "Файл должен быть .dll");

            }

            ImGui::SameLine(ImGui::GetWindowWidth() - 95.0f);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 4.0f);
            if (ImGui::Button("Обзор...", ImVec2(80, 28)))
                directoryPathForDll = openFileDialogForDll(hwnd);
        }
        ImGui::EndChild();

        ImGui::Spacing();

        ImGui::BeginChild("ProcessCard", ImVec2(0, 180), true, ImGuiWindowFlags_NoScrollbar);
        {
            ImGui::PushFont(fontSmall);
            ImGui::TextColored(ImVec4(0.55f, 0.58f, 0.65f, 1.00f), "ЦЕЛЕВОЙ ПРОЦЕСС");
            ImGui::PopFont();

            ImGui::SameLine(ImGui::GetWindowWidth() - 95.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 2));
            if (ImGui::Button("Обновить", ImVec2(80, 22)))
            {
                freeProcessList(processList);
                processList = getRunningProcesses(g_pd3dDevice);
                if (selectedProcessIdx >= (int)processList.size())
                    selectedProcessIdx = -1;
            }
            ImGui::PopStyleVar();

            std::string comboPreview = (selectedProcessIdx >= 0 && selectedProcessIdx < (int)processList.size())
                ? processList[selectedProcessIdx].displayName
                : (!selectedExeName.empty() ? selectedExeName + (selectedPid != 0 ? " (PID: " + std::to_string(selectedPid) + ")" : "") : "Выберите процесс из списка...");

            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::BeginCombo("##ProcessCombo", comboPreview.c_str()))
            {
                ImGui::InputTextWithHint("##ProcessFilter", "Поиск...", processSearchFilter, IM_ARRAYSIZE(processSearchFilter));
                ImGui::Separator();

                for (int n = 0; n < (int)processList.size(); n++)
                {
                    if (processSearchFilter[0] != '\0')
                    {
                        std::string filterLower = processSearchFilter;
                        std::string nameLower = processList[n].name;
                        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);
                        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

                        if (nameLower.find(filterLower) == std::string::npos)
                            continue;
                    }

                    if (processList[n].iconTexture)
                    {
                        ImGui::Image((ImTextureID)processList[n].iconTexture, ImVec2(16, 16));
                        ImGui::SameLine(0, 6);
                    }

                    const bool isSelected = (selectedProcessIdx == n);
                    if (ImGui::Selectable(processList[n].displayName.c_str(), isSelected))
                    {
                        selectedProcessIdx = n;
                        selectedPid = processList[n].pid;
                        selectedExeName = processList[n].name;
                    }

                    if (isSelected)
                        ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }

            ImGui::Spacing();
            
            if (selectedPid != 0)
                ImGui::TextColored(ImVec4(0.20f, 0.80f, 0.50f, 1.00f), "● Процесс активен (PID: %lu)", selectedPid);
            else
                ImGui::TextColored(ImVec4(0.50f, 0.52f, 0.58f, 1.00f), "○ Процесс не выбран");

            ImGui::Spacing();

            if (ImGui::Button("Выбрать .exe файл с диска...", ImVec2(ImGui::GetContentRegionAvail().x, 26)))
            {
                directoryPathForExe = openFileDialogForExe(hwnd);
                if (!directoryPathForExe.empty())
                {
                    selectedPid = findProcessPID(directoryPathForExe.c_str());
                    selectedExeName = std::filesystem::path(wstringToUtf8(directoryPathForExe)).filename().string();
                    selectedProcessIdx = -1;
                }
            }
        }
        ImGui::EndChild();

        ImGui::Spacing();

        ImGui::PopFont();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.39f, 0.40f, 0.95f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.46f, 0.98f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.32f, 0.33f, 0.82f, 1.00f));
        ImGui::PushFont(fontTitle);

        if (ImGui::Button("ИНЪЕКЦИЯ DLL", ImVec2(ImGui::GetContentRegionAvail().x, 40.0f)))
        {
            if (selectedPid == 0 && !directoryPathForExe.empty())
                selectedPid = findProcessPID(directoryPathForExe.c_str());

            if (directoryPathForDll.empty())
                outputFalls = "Ошибка: не выбран DLL файл";
            else if (selectedPid == 0)
                outputFalls = "Ошибка: процесс не выбран или не запущен";
            else
            {
                outputFalls = "";
                ManualMapDllInject(selectedPid, directoryPathForDll, outputFalls);
            }

            onClicedButtonForInjectDll++;
        }

        if (onClicedButtonForInjectDll > 0 && !outputFalls.empty())
        {
            ImGui::Spacing();
            bool isSuccess = (outputFalls.find("успешно") != std::string::npos || outputFalls.find("Success") != std::string::npos || outputFalls.find("success") != std::string::npos);
            
            ImVec4 bannerBg = isSuccess ? ImVec4(0.12f, 0.25f, 0.18f, 0.80f) : ImVec4(0.28f, 0.14f, 0.16f, 0.80f);
            ImVec4 textColor = isSuccess ? ImVec4(0.40f, 0.90f, 0.60f, 1.00f) : ImVec4(0.95f, 0.45f, 0.45f, 1.00f);

            ImGui::PushStyleColor(ImGuiCol_ChildBg, bannerBg);
            ImGui::BeginChild("StatusBanner", ImVec2(0, 40), true, ImGuiWindowFlags_NoScrollbar);
            {
                ImGui::SetCursorPosY(8.0f);
                float textWidth = ImGui::CalcTextSize(outputFalls.c_str()).x;
                ImGui::SetCursorPosX((ImGui::GetWindowWidth() - textWidth) * 0.5f);
                ImGui::TextColored(textColor, "%s", outputFalls.c_str());
            }
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }

        ImGui::PopFont();
        ImGui::PopStyleColor(3);


        ImGui::End();

        const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    // Очистка
    freeProcessList(processList);
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
}

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;

    switch (msg) 
    {
    case WM_SIZE:
    {
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    }
    case WM_SYSCOMMAND:
    {
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    }
    case WM_DESTROY:
    {
        ::PostQuitMessage(0);
        return 0;
    }
    }

    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}