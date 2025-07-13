#include "../imgui/imgui.h"
#include "../imgui/imgui_impl_win32.h"
#include "../imgui/imgui_impl_dx11.h"
#include "../imgui/imgui_internal.h"
#include <d3d11.h>
#include <filesystem>
#include "gui.h"
#include "searchDLL.h"
#include "searchPID.h"
#include "dll injection.h"
#include "..\\resource.h"

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

void window()
{
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"ImGui DX11", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"INJECTOR", WS_POPUPWINDOW, 100, 100, width, heigth, nullptr, nullptr, wc.hInstance, nullptr);

    HICON hIcon = (HICON)LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 64, 64, LR_DEFAULTCOLOR);
    SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);   // Панель задач, Alt+Tab
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon); // Заголовок окна

    // Инициализация DirectX
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
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // fonts
    ImFont* Arial = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", 18.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(Arial != NULL);

    ImFont* Arial17 = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", 17.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(Arial17 != NULL);

    ImFont* fontSize20 = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Corbel.ttf", 20.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(fontSize20 != NULL);

    ImFont* fontSize16 = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Corbel.ttf", 16.0f, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IM_ASSERT(fontSize16 != NULL);

    ImFont* titleBarFontIcon = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segmdl2.ttf", 20.0f, NULL, NULL);
    IM_ASSERT(titleBarFontIcon != NULL);

    ImFont* titleBarFontName = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", 18.0f, NULL, NULL);
    IM_ASSERT(titleBarFontName != NULL);

    // Переменные состояния
    bool show_demo = true;
    bool show_window = false;

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    std::wstring directoryPathForDll;
    std::wstring directoryPathForExe;

    while (windowExit) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) windowExit = false;
        }
        if (!windowExit) break;

        // Новый кадр ImGui 
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGuiStyle& style = ImGui::GetStyle();
        style.FrameRounding = 6.0f;
        style.Colors[ImGuiCol_WindowBg]      = ImVec4(6 / 255.0f, 25 / 255.0f, 31 / 255.0f, 1.0f);
        style.Colors[ImGuiCol_Text]          = ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f);
        style.Colors[ImGuiCol_Button]        = ImVec4(37 / 255.0f, 124 / 255.0f, 143 / 255.0f, 1.0f);
        style.Colors[ImGuiCol_ButtonHovered] = ImVec4(67 / 255.0f, 154 / 255.0f, 173 / 255.0f, 1.0f);
        style.Colors[ImGuiCol_ButtonActive]  = ImVec4(67 / 255.0f, 154 / 255.0f, 173 / 255.0f, 1.0f);

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin("DLL INJECTOR", &windowExit, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);
        
        if (ImGui::IsItemActive() && ImGui::IsMouseDown(ImGuiMouseButton_Left))
        {
            ReleaseCapture();
            SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);

            ImGui::ClearActiveID();
            ImGuiIO& io = ImGui::GetIO();
            io.MouseDown[0] = false;
            io.MouseReleased[0] = true;
        }

        ImGui::PushFont(titleBarFontName);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(110 / 255.0f, 122 / 255.0f, 128 / 255.0f, 1.0f));
        {
            ImGui::SetCursorPos(ImVec2(30, 35));
            ImGui::Text("INJECTOR");

            ImGui::SameLine();

            ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - ImGui::CalcTextSize("CLOSE").x - 40, 35));
            ImGui::Text("CLOSE");
            if (ImGui::IsItemClicked())
                windowExit = false;
        }
        ImGui::PopStyleColor();
        ImGui::PopFont();

        static int onClickedButtonForDll = 0;

        ImGui::SetCursorPos(ImVec2(20, 80));
        if (ImGui::Button("Выбрать dll", ImVec2(ImGui::CalcTextSize("Выбрать dll").x + 30, 45)))
        {
            directoryPathForDll = openFileDialogForDll(hwnd);
            onClickedButtonForDll++;
        }

        std::string directoryPathForDllConvert = std::filesystem::path(wstringToUtf8(directoryPathForDll)).filename().string();

        ImGui::PushFont(Arial);
        if (directoryPathForDllConvert.empty() && onClickedButtonForDll > 0)
        {
            ImGui::SetCursorPosX(20);
            ImGui::Text("Вы не выбрали DLL файл");
        }
        else if (onClickedButtonForDll > 0)
        {
            ImGui::SetCursorPosX(20);
            ImGui::Text("Вы выбрали: %s", directoryPathForDllConvert.c_str());
        }

        static int onClickedButtonForExe = 0;

        ImGui::SameLine();

        ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - ImGui::CalcTextSize("Выбрать exe").x - 55, 80));
        if (ImGui::Button("Выбрать exe", ImVec2(ImGui::CalcTextSize("Выбрать exe").x + 30, 45)))
        {
            directoryPathForExe = openFileDialogForExe(hwnd);
            onClickedButtonForExe++;
        }

        DWORD pid = findProcessPID(directoryPathForExe.c_str());

        std::string directoryPathForExeConvert = std::filesystem::path(wstringToUtf8(directoryPathForExe)).filename().string();

        if (directoryPathForExeConvert.empty() && onClickedButtonForExe > 0)
        {
            ImGui::SetCursorPosX(20);
            ImGui::Text("Вы не выбрали EXE файл");
        }
        else if (pid != 0 && onClickedButtonForExe > 0)
        {
            ImGui::SetCursorPosX(20);
            ImGui::Text("Вы выбрали: %s", directoryPathForExeConvert.c_str());
            ImGui::SetCursorPosX(20);
            ImGui::Text("PID процесса: %d", pid);
        }
        else if (pid == 0 && onClickedButtonForExe > 0)
        {
            ImGui::SetCursorPosX(20);
            ImGui::Text("Вы выбрали: %s", directoryPathForExeConvert.c_str());
            ImGui::SetCursorPosX(20);
            ImGui::Text("Процесс не запущен");
        }

        ImGui::PopFont();

        ImGui::PushFont(Arial17);
        
        static std::string outputFalls;
        static int onClicedButtonForInjectDll = 0;

        ImGui::SetCursorPos(ImVec2(135, 200));
        if (ImGui::Button("Инъекция DLL в EXE", ImVec2(ImGui::CalcTextSize("Инъекция DLL в EXE").x + 30, 45)))
        {
            dllInject(pid, directoryPathForDll, outputFalls);
            onClicedButtonForInjectDll++;
        }

        if (onClicedButtonForInjectDll > 0)
        {
            ImGui::SetCursorPosX((ImGui::GetWindowWidth() / 2) -
                (ImGui::CalcTextSize(outputFalls.c_str()).x / 2));
            ImGui::Text(outputFalls.c_str());
        }

        ImGui::PopFont();

        ImGui::End();



        // Рендеринг
        const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    // Очистка
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

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }

    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}