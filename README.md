# DLL Injector — Manual Map

Инжектор DLL с реализацией ручного отображения (manual map) в целевой процесс. Не использует `LoadLibrary` — DLL загружается вручную через прямое взаимодействие с памятью процесса посредством Nt* API.

---

## Возможности

### Инжекция
- Manual Map — DLL загружается без вызова `LoadLibrary`, не попадает в PEB/LDR процесса
- Парсинг и применение таблицы релокаций (`.reloc`)
- Патчинг IAT: разрешение импортов по имени и по ординалу
- Рекурсивное отображение зависимостей (если зависимость не загружена в процессе — маппируется тоже)
- Поддержка TLS-коллбэков
- Регистрация таблицы исключений через `RtlAddFunctionTable` (поддержка SEH / C++ exceptions в x64)
- Исполнение шеллкода через hijack потока (`NtSuspendThread` → `NtGetContextThread` → подмена RIP → `NtSetContextThread` → `NtResumeThread`)

### Шеллкод (x64 MASM)
- Полное сохранение и восстановление контекста: все GPR (`rax`–`r15`), `rflags`, XMM регистры (`xmm1`–`xmm15`)
- Выравнивание стека по 16 байт перед вызовом
- Вызов TLS-коллбэков в цикле перед `DllMain`
- Запись `Done = 1` по завершению — инжектор ожидает этого флага перед продолжением

### Системные вызовы (Silent* обёртки)
- Прямые вызовы Nt* API: `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory`, `NtSuspendThread`, `NtResumeThread`, `NtGetContextThread`, `NtSetContextThread`, `NtClose`, `NtOpenThread`, `NtQueryAttributesFile`
- Поиск адресов функций через PEB walking (без `GetProcAddress`)
- Поддержка форвардинга экспортов
- Форварды `api-ms-win-*` / `ext-ms-*` перенаправляются в `kernelbase.dll` / `kernel32.dll`; `api-ms-win-crt-*` — в `ucrtbase.dll`

### GUI
- ImGui + DirectX 11
- Список запущенных процессов с иконками (дедупликация по имени)
- Выбор DLL через диалог файла
- Вывод статуса инжекции

---

## Как использовать

1. Запусти `Injector.exe`
2. Выбери DLL для инжекции
3. Выбери целевой процесс из списка
4. Нажми кнопку инжекции — DLL будет отображена в память процесса

---

## Сборка

- C++20, MSVC
- x64 MASM (`.asm` компилируется через ML64)
- Зависимости: ImGui, DirectX 11 SDK, `ntdll.lib`

---

## Ограничения

- Поддерживаются только x64 процессы и DLL
- Антивирусы могут детектировать инжектор (Nt* API + thread hijack)
- Проект создан в образовательных целях