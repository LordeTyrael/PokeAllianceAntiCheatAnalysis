# PokeAlliance — Anti-Cheat / Anti-Analysis Audit

> PokeAlliance has a large botting scene, but the staff are constantly changing
> their anti-bot methods — anything in this document can be obsolete tomorrow.
>
> The game is growing fast, so there is a good chance the staff add a **kernel-mode anti-cheat** at some
> point. If I remember correctly, PokeAlliance did ship an anti-cheat before — most likely user-mode —
> which was later removed because of false positives.
>
> **I do not recommend using a bot.** The client is not what will catch you; the server is. If its
> heuristics flag you, a GM comes and checks you by hand, and no amount of client-side work protects
> you from that.
>
> This is **mostly static analysis**, and I will keep updating it over time as the client and the
> server-side behaviour change.
>
> *Last updated 2026-09-09 — analysed build: 2026-08-28.*

PokeAlliance is a PokeTibia (an OTCv8-based Pokémon MMO). This document answers one question about its client `PokeAlliance_dx.exe` (x86-64 PE, ~36 MB, base `0x140000000`, MSVC C++, ~57,771 functions): does it try to stop you from debugging, hooking, or tampering with it?

Short answer: **not locally — but it reports everything it can see to the server.** There is no anti-debugging, no anti-hooking, and no code-integrity check anywhere in the binary. What exists instead is a server-controlled telemetry suite: at any moment the server can ask the client to enumerate every running process, every loaded DLL, and every window title, and it uploads a full hardware fingerprint at login. Every punitive decision is made server-side.

## 1. Verdict Table

| Category | Verdict |
|---|---|
| IsDebuggerPresent / CheckRemoteDebuggerPresent | Absent from game code (all 40 refs sit in the CRT range) |
| NTDLL anti-debug (`NtQueryInformationProcess`, `NtSetInformationThread`) | Absent from imports and strings |
| Manual PEB checks (`BeingDebugged`, `NtGlobalFlag`) | None |
| Timing traps (QPC / GetTickCount / RDTSC deltas) | None — RDTSC only in OpenSSL capability asm |
| `.text` CRC / INT3 (0xCC) breakpoint scanning | None in game logic |
| IAT / inline hook detection | None |
| VM / sandbox detection | None (the only "vmware" strings are FFmpeg codec names) |
| Kernel driver / watchdog | None |
| Process enumeration | **Present** — server-triggered, opcode `0x50` |
| Loaded-module (DLL) enumeration | **Present** — server-triggered, opcode `0x51` |
| Window-title enumeration | **Present** — server-triggered, opcode `0x52` |
| Hardware fingerprinting | **Present** — uploaded at login, re-requestable mid-session |
| Startup blacklists (process / file / DLL checksum) | **Present** — Lua-configured, self-terminates on a hit |
| Server-driven visual bot check | **Present** — opcode `0x5EA` |
| Bot-protection gate on protected `g_game` Lua calls | **Present** — stock OTCv8 behaviour, not a PokeAlliance addition |

## 2. Server-Controlled Environment Inventory

Three opcodes, all reachable from the game-packet dispatcher (`FUN_14041d600`) at any time during a session. They are **on-demand** — in ~3.5 minutes of logged-in observation none fired, which is why they only surface in a dispatcher decompilation.

| Opcode | Handler | Collector | Payload |
|---|---|---|---|
| `0x50` | `FUN_1404490f0` | `FUN_140755eb0` — `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Next` | every process name (`PROCESSENTRY32.szExeFile`) |
| `0x51` | `FUN_140449260` | `FUN_140755c70` — `GetCurrentProcess` + `EnumProcessModules` + `GetModuleFileNameExA` | every loaded DLL, **full absolute path** |
| `0x52` | `FUN_1404493d0` | `FUN_140756240` — `EnumWindows` → `GetWindowTextA` | every top-level window title |

All three are byte-for-byte isomorphic. Wire format:

```c
collector(0, &vec);                                     // fill the vector
OutputMessage msg;
msg.addU16(0x50);                                       // reply opcode
msg.addU32((end - begin) >> 5);                         // count, stride 0x20
for (p = begin; p != end; p += 0x20)
    msg.addString(p);                                   // one entry per string
send(msg);
```

The send goes through `_guard_dispatch_icall` (Control Flow Guard), so no direct call edges appear — searching for xrefs to the collectors finds nothing, which is how these stayed hidden on the first pass.

**There are two collector clusters, and they are not cleanly split by consumer.** The handlers above use a newer cluster around `0x140755xxx`; an older one around `0x140752xxx` survives alongside it:

| Cluster | Functions | Wired to |
|---|---|---|
| `0x140755xxx` | `FUN_140755eb0` (processes), `FUN_140755c70` (modules), `FUN_140756240` (windows) | **both** — opcodes `0x50`/`0x51`/`0x52` *and* the startup scanner `FUN_1407c7cc0` |
| `0x140752xxx` (legacy) | `FUN_140752800` — process **and** module enumeration merged into one function; `FUN_1407531e0` (windows) | startup scanner only — and `FUN_1407531e0` has **zero call sites** |

So the same two collectors feed the local blacklist check *and* the server reporters; only the consumers differ (local compare vs. `addString` onto the wire).

**There is no filtering of any kind.** No allow-list, no deny-list, no path normalisation, no dedup, no case folding. Whatever is in the PEB `InLoadOrderLinks` goes on the wire verbatim, capped at 1024 modules × 260 chars.

A live `0x51` dump from a **cleanly launched** client (no debugger, no injected DLLs):

| Metric | Value |
|---|---|
| modules reported | **74** |
| payload size | **2,941 bytes** |
| Windows system DLLs | 67 |
| from the game directory | 4 — `PokeAlliance_dx.exe`, `libGLESv2.dll`, `libEGL.dll`, `d3dcompiler_47.dll` |
| GPU driver (AMD DriverStore) | 3 — `amdxx64.dll`, `amdenc64.dll`, `amdihk64.dll` |

Two consequences worth stating plainly:

- **A whitelist is impossible.** 67 of 74 entries are OS DLLs that vary by Windows build; the rest vary by GPU vendor, driver version (`...\<inf>.inf_amd64_<driver-hash>\B0xxxxx\...` — a per-machine DriverStore path), install path and Windows username. Only the 4 game-directory entries are stable.
- **`dbghelp.dll` and `dbgcore.dll` are present in a 100% clean client** — the client ships a crash dumper that loads them at startup. Any "debugger DLL present" heuristic bans everyone.

So `0x51` cannot be a self-sufficient real-time ban trigger. It is either a substring blacklist (`frida`, `cheat`, `inject`, …) or a store-for-review forensic reporter — evidence collected now, judged later.

**Visibility**, which is the only part a defender can rely on:

| Invisible to `0x51` | Visible the moment it fires |
|---|---|
| pure-Lua modules — not DLLs | `frida-agent.dll` — Frida injects via remote `LoadLibrary`, so it lands in the PEB list |
| manually-mapped images that unlink from `InLoadOrderLinks` | anything loaded via `LoadLibrary` / `LdrLoadDll` |
| anything living in another process | hook libraries installed via `SetWindowsHookEx` |
| kernel-mode components | overlays that inject (RTSS, Discord, Steam, MSI Afterburner) |

### Observing it from Lua — and when it actually fires

Every inbound packet emits the Lua signal **`onOpcode`** (string @ `0x141db5a80`) *before* native dispatch, so a Lua module can log the opcode stream without touching the binary. This matters because **no shipped Lua module uses any of the anti-cheat bindings** — `getHWID`, `isProcessRunning`, `checkBotProtection` and the checksum functions appear in the client's own scripts nowhere. The reporting is entirely native; Lua is only a bystander, and that bystander can watch.

What it watches, however, is mostly nothing. **None of the three reporters has ever been observed firing:**

- ~3.5 minutes of logged-in play: zero `0x50` / `0x51` / `0x52` requests, zero `0x5EA` challenges.
- A passive Frida tracer that hooked all three senders and histogrammed **every** inbound opcode — roughly **an hour of instrumented play across 9 sessions** — recorded **not a single sender invocation**. The server never once asked for an inventory.

The tracer was demonstrably working: over the same runs it caught `0x1F` (fingerprint re-request) firing at the login screen and a steady stream of custom-block opcodes (`0x5DD`, `0x5F1`, `0x5F5`, `0x606`, `0x627`). Only the three inventory reporters stayed silent.

Whatever arms them, it is not a short burst of unusual input. The most plausible reading is that the server scores behaviour over a long session and only pulls the environment inventory once a threshold is crossed — i.e. triggering detection likely requires sustained, repetitive play rather than any single action. That threshold and its heuristics live entirely server-side and are not observable from this binary.

### The visual bot check — opcode `0x5EA`

`ProtocolGame::parseGameServerCheckBot` (`FUN_140430980`, identified by its own mangled symbol in the error path) reads two u16 coordinates plus flag bytes, then loops a count byte of effect IDs. Each ID resolves through the thing-type table (category 2 = Effect) and spawns an object at that position with three `rand()%256`-scaled float offsets and highlight fields set. Invalid IDs log `"invalid effect id %d"`.

It is a **server-driven captcha decoy**: a client that does not implement this custom opcode never reacts, and the absence of a reaction is itself the detection signal.

## 3. Hardware Fingerprinting

A collector cluster around `0x140750000–0x140754000`:

| Function | API / source | Output |
|---|---|---|
| `FUN_1407518f0` | `GetAdaptersInfo` — MAC bytes at struct `+0x199..+0x19f` | hex MAC string(s) |
| `FUN_140751d50` | `GetSystemFirmwareTable('RSMB')` | raw SMBIOS tables |
| `FUN_140752430` | `CreateFileA("\\\\.\\PhysicalDrive0")` + `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` | physical disk serial |
| `FUN_140751c00` | `RegOpenKeyExA(HKLM\SOFTWARE\Microsoft\Cryptography)` → `MachineGuid` | MachineGuid |
| `FUN_140751340` | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString` | CPU model |
| `FUN_140751b60` | `GetUserNameA` | Windows username |
| — | `GlobalMemoryStatusEx` | total RAM |

`getHWID` (`FUN_1407526c0`) concatenates MachineGuid + SMBIOS + disk serial into one `u:` / `d:` / `g:`-prefixed identifier, exposed to Lua as `g_platform.getHWID`.

The sender (`FUN_14046a800`) writes **client→server opcode `0x000A`** and appends: machine identifier, Windows username, CPU model, total RAM, MAC list, combined HWID, and the OTCv8 client-id string. It emits the Lua signal `getLoginExtendedData` first so modules can append fields, then transmits.

It fires on **every game connection** (ProtocolGame connect path) and again whenever the server sends **opcode `0x1F`** — a mid-session re-request. Dynamic tracing shows this happening at the login screen, before character select.

## 4. Local Blacklists — Configured in `init.lua`, Enforced Natively

Four plaintext globals in the (encrypted) `init.lua`, read by the startup scanner `FUN_1407c7cc0`:

```lua
DLL_CHECKSUM   = { {"d3dcompiler_47.dll","d30621d9"}, {"libEGL.dll","792836ce"}, {"libGLESv2.dll","9b805101"} }
BAD_FILES      = {"lam", "engine.spr", "LanEngine.key", "LanEngine.dll", "opengl32.dll"}
BAD_PROCESSES  = {"NinjaRipper.exe", "injhelper.exe", "ripdump.exe"}
BAD_DLLS       = {"intruder.dll", "d3dx8d.dll", "d3dwrap.dll"}
```

These are byte-identical across every build on disk since at least 2026-08-07 — the list has never been updated. The scanner runs four checks and appends each hit to a 12-slot violation struct:

| Check | Method | Verdict |
|---|---|---|
| `DLL_CHECKSUM` | recompute digest per DLL, compare to the hex in `init.lua` | works |
| `BAD_FILES` | build path, test existence | works |
| `BAD_PROCESSES` | `std::find` over the process list | works |
| `BAD_DLLS` | `std::find` over the module list | **can never match** |

The matcher (`FUN_1407cab20`) is a bare `std::find` with exact, case-sensitive `memcmp` — length must match first, then a full compare. No substring matching, no path normalisation, no case folding:

```c
while (((_Size != sVar2) || (_Size != 0 && memcmp(_Buf1, _Buf2, _Size) != 0))
       && (param_2 += 4, param_2 != param_3));
```

**`BAD_DLLS` is dead code.** The two collectors return different shapes: the process lister yields bare names (`NinjaRipper.exe`), the module lister yields full absolute paths (`C:\Windows\SYSTEM32\ntdll.dll` — 74/74, confirmed empirically). `BAD_PROCESSES` compares bare names against bare names and matches; `BAD_DLLS` compares bare names against full paths and fails the length test immediately. Whoever wrote it copy-pasted the process check without stripping the directory component.

On any hit the client terminates itself:

```c
PostMessageA(hwnd, 0x10 /* WM_CLOSE */, 0, 0);   // FUN_140516740
```

Traced live on the 2026-08-23 build, this path fires **unconditionally at startup** and posts to `hwnd = 0x0` — `DAT_143754c78` is not yet populated that early, so it is a no-op and a clean launch survives. The startup "self-termination" appears to be a botched splash-window teardown rather than working self-protection.

**Net effect:** local enforcement reduces to 3 DLL CRC32 checks, 5 file-existence checks and 3 process-name checks. Nothing on the list is modern — no Frida, Cheat Engine, x64dbg, ReClass, IDA, Process Hacker, Wireshark, AutoIt or AHK, no overlays, and not `dbghelp`. `d3dx8d.dll` / `d3dwrap.dll` / `intruder.dll` are mid-2000s DirectX-8-wrapper-era tooling.

## 5. The Bot-Protection Gate

`FUN_1402dab30`, registered as Lua binding `g_game.checkBotProtection`. It cancels a call to a protected `g_game` function when the game-object feature bit `0x800000000` at `+0x238` is set, the in-game flag at `+0x16a` is set, and the call originated from Lua, then logs:

```
caught a lua call to a bot protected game function, the call was cancelled
```

An earlier reading assumed the additional guard bytes were a server-driven "arm" flag. They are not: one is the generic Lua→C call-nesting counter (incremented and decremented around every C-closure dispatch), one is a `GraphicalApplication` field zeroed in the app constructor and never written again, and one is never written at all. **Nothing server-side arms this gate** — arming is the feature bit, which arrives with the game-feature set. This is stock OTClient behaviour, not a PokeAlliance addition.

## 6. What Was Searched For and NOT Found

| Technique | Search method | Result |
|---|---|---|
| `CheckRemoteDebuggerPresent` | Import table + strings | Absent |
| `NtQueryInformationProcess` | Imports + strings | Absent |
| `NtSetInformationThread` (ThreadHideFromDebugger) | Imports + strings | Absent |
| PEB `BeingDebugged` / `NtGlobalFlag` | Byte patterns (`65 48 8b 04 25 60 00 00 00` = `gs:[0x60]`) | Zero matches |
| `IsDebuggerPresent` in game logic | All 40 IAT refs | All in the CRT range `0x1415C8B17–0x1415F5133`, error handling only |
| RDTSC delta trap | Decompilation of every `0F 31` site | None — all in OpenSSL capability asm or decoding artifacts |
| `INT3` (0xCC) scan over `.text` | Byte pattern scan | Absent |
| `.text` CRC / self-integrity loop | Accumulation-loop patterns | Absent (only updater file hashing, §4) |
| IAT / inline hook detection | Module enumeration scan | Absent |
| VM / sandbox detection | String scan + device probes | Absent — only FFmpeg codec-table literals |
| `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `CreateRemoteThread`, `SetWindowsHookEx`, `GetAsyncKeyState`, `Thread32First/Next` | Import table | **Absent from the import table entirely** |
| Self-modifying code | `VirtualProtect` / `VirtualQuery` sites | All in CRT / CFG support range |
| `CPUID` | — | Only in OpenSSL capability detection |
| Screenshot exfiltration | `doScreenshot` XREFs | Plain user-facing feature, no network use |

## 7. Conclusion

PokeAlliance defends itself in exactly one place: **the server**. The client is an informant, not a guard.

- It has **no self-defence**: no anti-debugging, no anti-hooking, no code-integrity checks, no driver, no watchdog. A debugger can be attached and the process stays stable.
- It has **extensive reporting**: full hardware fingerprint at login and on demand (`0x1F`), plus on-demand process / module / window inventories (`0x50` / `0x51` / `0x52`) that expose any injected DLL, cheat-tool window or debug agent.
- Its **local** enforcement is minimal and stale — 11 checks against a blacklist unchanged since 2026-08-07, one of the four lists non-functional, and a self-termination path that posts to a null window handle.
- Its **server-side** verdict logic is not observable from the binary.
- The inventory reporters are **dormant in practice**. Neither ordinary play nor ~1 hour of instrumented tracing ever triggered `0x51`; the most plausible trigger is sustained repetitive behaviour scored over a long session, not any single action.

The practical asymmetry: a **pure-Lua** module is invisible to every local check (no DLL, no file, no process) and adds nothing to the `0x51` module list. Anything that injects a DLL — Frida included — is reported verbatim the moment the server asks.

## Appendix — Addresses (2026-08-28 build, base `0x140000000`)

Shift on every recompile. The 2026-08-23 build had the same architecture with everything ≈ `0x4100` lower in `.rdata` and several functions relocated.

| Role | Address |
|---|---|
| Game-packet dispatcher | `0x14041d600` |
| Custom-opcode jump table (`0x5DD–0x634`) | `switchdataD_14041f6fc` |
| `parseGameServerCheckBot` (opcode `0x5EA`) | `0x140430980` |
| `0x50` handler / process collector | `0x1404490f0` / `0x140755eb0` |
| `0x51` handler / module collector | `0x140449260` / `0x140755c70` |
| `0x52` handler / window collector | `0x1404493d0` / `0x140756240` |
| Login extended-data sender (opcode `0x000A`) | `0x14046a800` |
| MAC collector (`GetAdaptersInfo`) | `0x1407518f0` |
| SMBIOS reader (`GetSystemFirmwareTable`) | `0x140751d50` |
| Disk serial reader (`PhysicalDrive0`) | `0x140752430` |
| `MachineGuid` registry reader | `0x140751c00` |
| CPU name reader | `0x140751340` |
| `GetUserNameA` wrapper | `0x140751b60` |
| `getHWID` combiner | `0x1407526c0` |
| `FindWindowA` wrapper (`isProcessRunning`) | `0x140750800` |
| Startup scanner / orchestrator | `0x1407c9040` / `0x1407c7cc0` |
| `BAD_*` / `DLL_CHECKSUM` string matcher (`std::find`) | `0x1407cab20` |
| Terminator (`PostMessageA(WM_CLOSE)`) | `0x140516740` |
| `checkBotProtection` guard | `0x1402dab30` |
| `selfChecksum` / `filesChecksums` / `fileChecksum` | `0x140510520` / `0x14050e4b0` / `0x14050e080` |
