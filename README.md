# PokeAlliance — Anti-Cheat / Anti-Analysis Audit

> **Read this first.** PokeAlliance has a large botting scene, but the staff are constantly changing  
> their anti-bot methods — anything in this document can be obsolete tomorrow.
>
> The game is growing fast, so there is a good chance the staff add a **kernel-mode anti-cheat** at some  
> point. If I remember correctly, PokeAlliance did ship an anti-cheat before — most likely user-mode —  
> which was later removed because of false positives. As of the 2026-09-15 build a user-mode one is  
> back, and it is a different design from the one that was removed — see §3.
>
> **I do not recommend using a bot.** The client is not what will catch you; the server is. If its  
> heuristics flag you, a GM comes and checks you by hand, and no amount of client-side work protects  
> you from that.
>
> This is **mostly static analysis**, (will do dynamic soon), and I will keep updating it over time as the client and the  
> server-side behaviour change.
>
> *Last updated 2026-09-15 — analysed build: 2026-09-15.*

PokeAlliance is a PokeTibia (an OTCv8-based Pokémon MMO). This document answers one question about its client `PokeAlliance_dx.exe` (x86-64 PE, ~36 MB, base `0x140000000`, MSVC C++, ~57,526 functions): does it try to stop you from debugging, hooking, or tampering with it?

Short answer: **not locally — but it reports everything it can see to the server.** There is no anti-debugging, no anti-hooking, and no code-integrity check anywhere in the binary. What exists instead is a server-controlled telemetry suite: at any moment the server can ask the client to enumerate every running process, every loaded DLL, and every window title, and it uploads a full hardware fingerprint at login. Every punitive decision is made server-side. The one local check it used to have — an `init.lua` blacklist — was removed in the 2026-09-09 build (§5), and the 2026-09-15 build adds something narrower in its place: a scanner that reports the processes holding a handle to the client, plus a memory tripwire (§3).

Section 3, and the reporter addresses in §2, are from the 2026-09-15 build. Sections 4–7 are from the 2026-09-09 build unless a row says otherwise. The 2026-09-15 build was diffed against 2026-09-09 and added no anti-debugging, anti-hooking or code-integrity check.


## 1. Verdict Table

| Category                                                                 | Verdict                                                                                               |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| IsDebuggerPresent / CheckRemoteDebuggerPresent                           | Absent from game code (all 40 refs sit in the CRT range)                                              |
| NTDLL anti-debug (`NtQueryInformationProcess`, `NtSetInformationThread`) | Absent from imports and strings                                                                       |
| Manual PEB checks (`BeingDebugged`, `NtGlobalFlag`)                      | None                                                                                                  |
| Timing traps (QPC / GetTickCount / RDTSC deltas)                         | None — RDTSC only in OpenSSL capability asm                                                           |
| `.text` CRC / INT3 (0xCC) breakpoint scanning                            | None in game logic                                                                                    |
| IAT / inline hook detection                                              | None                                                                                                  |
| VM / sandbox detection                                                   | None (the only "vmware" strings are FFmpeg codec names)                                               |
| Kernel driver / watchdog                                                 | None                                                                                                  |
| Process enumeration                                                      | **Present** — server-triggered, opcode `0x50`                                                         |
| Loaded-module (DLL) enumeration                                          | **Present** — server-triggered, opcode `0x51`                                                         |
| Window-title enumeration                                                 | **Present** — server-triggered, opcode `0x52`                                                         |
| Process handle-table scan (who holds a handle to the client)             | **Present** — server-triggered, opcode `0x638`                                                        |
| File hashing + Authenticode verification of other processes              | **Present** — same opcode                                                                             |
| Memory-tamper tripwire (guard page + canary)                             | **Present** — armed on the first `0x638`                                                              |
| Hardware fingerprinting                                                  | **Present** — uploaded at login, re-requestable mid-session                                           |
| Startup blacklists (process / file / DLL checksum)                       | **Removed** — nothing in the client reads them, and the 2026-09-15 `init.lua` no longer contains them |
| Server-driven visual bot check                                           | **Present** — opcode `0x5EA`                                                                          |
| Bot-protection gate on protected `g_game` Lua calls                      | **Present** — stock OTCv8 behaviour, not a PokeAlliance addition                                      |


## 2. Server-Controlled Environment Inventory

Three opcodes, all reachable from the game-packet dispatcher (`FUN_140418e10`) at any time during a session. They are **on-demand** — in ~3.5 minutes of logged-in observation none fired, which is why they only surface in a dispatcher decompilation. The 2026-09-15 build moved the dispatcher and all three collectors.

| Opcode | Handler                  | Collector                                                                                     | Payload                                         |
| ------ | ------------------------ | --------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `0x50` | `FUN_140418e10` (inline) | `FUN_1407570c0` — `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Next`      | every process name (`PROCESSENTRY32.szExeFile`) |
| `0x51` | `FUN_1404461a0`          | `FUN_140756e80` — `GetCurrentProcess` + `EnumProcessModules` + `GetModuleFileNameExA`         | every loaded DLL, **full absolute path**        |
| `0x52` | `FUN_140446310`          | `FUN_140757450` — `EnumWindows(FUN_1407572c0, 0)`; callback `GetWindowTextA(hwnd, buf, 0x32)` | every top-level window title, 2+ chars          |

The wire format is identical for all three:

```c
collector(0, &vec);                                     // fill the vector
OutputMessage msg;
msg.addU16(0x50);                                       // reply opcode
msg.addU32((end - begin) >> 5);                         // count, stride 0x20
for (p = begin; p != end; p += 0x20)
    msg.addString(p);                                   // one entry per string
send(msg);
```

The send goes through `_guard_dispatch_icall` (Control Flow Guard), so the transmit itself has no direct call edge.

**There is exactly one collector per list, and each has exactly one caller.** `CreateToolhelp32Snapshot`, `EnumProcessModules` and `EnumWindows` each appear at a single call site in the whole binary, and querying the callers of the three collectors returns only the handler from the table above. The second consumer that used to exist — the local blacklist scanner, which re-used the same three collectors to compare against the `init.lua` lists — is gone as of the 2026-09-09 build (§5). The collectors now feed the server reporters and nothing else.

**The module list has no filtering of any kind.** No allow-list, no deny-list, no path normalisation, no dedup, no case folding. Whatever is in the PEB `InLoadOrderLinks` goes on the wire verbatim, capped at 1024 modules × 260 chars. The window list has exactly one filter: `GetWindowTextA` reads into a 50-byte buffer, and a title is kept only if its length is greater than 1 — so titles truncate at 49 characters and one-character titles never ship.

A live `0x51` dump from a **cleanly launched** client (no debugger, no injected DLLs):

| Metric                       | Value                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------ |
| modules reported             | **74**                                                                         |
| payload size                 | **2,941 bytes**                                                                |
| Windows system DLLs          | 67                                                                             |
| from the game directory      | 4 — `PokeAlliance_dx.exe`, `libGLESv2.dll`, `libEGL.dll`, `d3dcompiler_47.dll` |
| GPU driver (AMD DriverStore) | 3 — `amdxx64.dll`, `amdenc64.dll`, `amdihk64.dll`                              |

Two consequences:

- **A whitelist is impossible.** 67 of 74 entries are OS DLLs that vary by Windows build; the rest vary by GPU vendor, driver version (`...\<inf>.inf_amd64_<driver-hash>\B0xxxxx\...` — a per-machine DriverStore path), install path and Windows username. Only the 4 game-directory entries are stable.
- **`dbghelp.dll` and `dbgcore.dll` are present in a 100% clean client** — the client ships a crash dumper that loads them at startup. Any "debugger DLL present" heuristic bans everyone.

So `0x51` cannot be a self-sufficient real-time ban trigger. It is either a substring blacklist (`frida`, `cheat`, `inject`, …) or a store-for-review forensic reporter — evidence collected now, judged later.

**Visibility** is the only part a defender can use:

| Invisible to `0x51`                                        | Visible the moment it fires                                                             |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| pure-Lua modules — not DLLs                                | `frida-agent.dll` — Frida injects via remote `LoadLibrary`, so it lands in the PEB list |
| manually-mapped images that unlink from `InLoadOrderLinks` | anything loaded via `LoadLibrary` / `LdrLoadDll`                                        |
| anything living in another process                         | hook libraries installed via `SetWindowsHookEx`                                         |
| kernel-mode components                                     | overlays that inject (RTSS, Discord, Steam, MSI Afterburner)                            |

The custom-opcode range on the 2026-09-15 build is `0x5DD–0x639` (0x5D entries), alongside a second dispatch table covering `0x51–0x11D`. The 2026-09-09 build added `0x635`–`0x637`, all gameplay — `0x636` / `0x637` are the training-camp packet that fires the `onTrainingCamp*` Lua signals, matching the `game_trainingcamp` module, and `0x11D` is the payments / streamer-code path. The 2026-09-15 build adds `0x638` and `0x639`: `0x638` is the anti-cheat slot (§3), and `0x639` is a pinned-text UI display.


### Observing it from Lua — and when it fires

Every inbound packet emits the Lua signal **`onOpcode`** (string @ `0x141d9c5d0`) *before* native dispatch, so a Lua module can log the opcode stream without touching the binary. This matters because **no shipped Lua module uses `getHWID`, `isProcessRunning` or `checkBotProtection`** — they appear in the client's own scripts nowhere. The reporting is entirely native; Lua is only a bystander, and that bystander can watch.

It arrives as `ProtocolGame:onOpcode(opcode, msg)`, and `msg` is a real `InputMessage` (`getU8` / `getU16` / `getU32` / `getString` / `getTable`), so a hook can read the payload and not just the opcode number. The dispatcher saves the message read cursor before the call and restores it before the native switch, so a hook can parse freely. The return value is the part to watch: `ProtocolGame:onOpcode` returns `true` as soon as any callback matches the opcode, and `true` skips native dispatch. `ProtocolGame.registerOpcode(0x638, …)` therefore disables `parseAntiCheat`; wrap `ProtocolGame.onOpcode` and return the original's result instead.

What it watches, however, is mostly nothing. **None of the three reporters has ever been observed firing:**

- ~3.5 minutes of logged-in play: zero `0x50` / `0x51` / `0x52` requests, zero `0x5EA` challenges.
- A passive Frida tracer that hooked all three senders and histogrammed **every** inbound opcode — roughly **an hour of instrumented play across 9 sessions** on the 2026-08-23 build — recorded **not a single sender invocation**. The server never once asked for an inventory.

The tracer was demonstrably working: over the same runs it caught `0x1F` (fingerprint re-request) firing at the login screen and a steady stream of custom-block opcodes (`0x5DD`, `0x5F1`, `0x5F5`, `0x606`, `0x627`). Only the three inventory reporters stayed silent.

Whatever arms them, it is not a short burst of unusual input. Most likely the server scores behaviour over a long session and only pulls the environment inventory once a threshold is crossed — i.e. triggering detection likely requires sustained, repetitive play rather than any single action. That threshold and its heuristics live entirely server-side and are not observable from this binary.

### The visual bot check — opcode `0x5EA`

`ProtocolGame::parseGameServerCheckBot` (`FUN_14042b5a0`, identified by its own mangled symbol in the error path) reads two u16 coordinates plus flag bytes, then loops a count byte of effect IDs. Each ID resolves through the thing-type table (category 2 = Effect) and spawns an object at that position with three `rand()%256`-scaled float offsets and highlight fields set. Invalid IDs log `"invalid effect id %d"`.

It is a **server-driven captcha decoy**: a client that does not implement this custom opcode never reacts, and the absence of a reaction is itself the detection signal.


## 3. The Handle-Table Scanner (2026-09-15 build)

The 2026-09-15 build adds a native component that did not exist on 2026-09-09. It is server-driven by opcode `0x638` — the handler is a private `ProtocolGame` member whose own RTTI name is `parseAntiCheat`. It arms a tripwire, queues a scan task, and answers **on the same opcode**.

It does **not** enumerate the process list. It reads the kernel **handle table** and reports the processes that currently hold a handle to the client:

| Step      | What it does                                                                           |
| --------- | -------------------------------------------------------------------------------------- |
| enumerate | `NtQuerySystemInformation` with class `0x40` (`SystemExtendedHandleInformation`)       |
| pass 1    | locate the client's own process object and its own handle in the table                 |
| pass 2    | every other entry whose `Object` matches, skipping the client's own PID and PID 4      |
| filter    | `GrantedAccess & 0x38` = `PROCESS_VM_OPERATION \| PROCESS_VM_READ \| PROCESS_VM_WRITE` |
| per PID   | resolve the image path, hash the file, verify its Authenticode signature               |
| reply     | send it back on `0x638`                                                                |

`NtQuerySystemInformation` is resolved at runtime with `GetProcAddress(GetModuleHandleA("ntdll.dll"), …)`, so it is not in the import table. The scan enables `SeDebugPrivilege` first (`LookupPrivilegeValueW` + `AdjustTokenPrivileges`). Nothing branches on the result: the enumeration runs either way, and only the failure status is recorded.

The scan task is posted to the client's general async task queue — the same queue the rest of the client uses — rather than being sent inline, so collection and transmission are separate events.


### What it reports

Per process, in wire order:

| Field  | Content                                                           |
| ------ | ----------------------------------------------------------------- |
| path   | full image path, **truncated to 96 characters**                   |
| signer | Authenticode signer **display name**                              |
| hash   | **SHA-256** of the file, lowercase hex — **skipped above 256 MB** |
| flag 1 | signature valid (`WinVerifyTrust` returned 0)                     |
| flag 2 | whether that process's handle includes write access               |

Once per report it also sends the client's own hash, signer name and signature-valid flag, the raw `NtQuerySystemInformation` status, the system-wide handle count, the client's own handle count, a check-flags bitfield, and a status code.

The hash is a plain file read (`CreateFileW` → `ReadFile` loop → `BCryptHashData`), not a memory image. Signature verification is `WinVerifyTrust` against `WINTRUST_ACTION_GENERIC_VERIFY_V2` with `WTD_UI_NONE`, after which the embedded PKCS#7 is pulled with `CryptQueryObject` and the signer resolved with `CertFindCertificateInStore` + `CertGetNameStringW`. All of it is silent — there is no prompt.

### It does not scan the filesystem

There is no directory or drive enumeration anywhere in the component: zero `FindFirstFile*` call sites, and `GetLogicalDrives` / `FindFirstVolumeW` / `GetVolumeInformationW` are not imported at all. It opens **specific files by path** in order to hash them, and does nothing else.

So an executable sitting idle on disk produces nothing. Only a **running** process that holds a memory-capable handle to the client can appear in a report — and a tool that opens the client, does its work and closes the handle before the scan runs leaves no trace in it.

### The tripwire

The first `0x638` of the process lifetime also arms a two-tier memory tripwire:

| Tier         | Detection                                                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| guarded page | a page allocated `PAGE_READWRITE`, then re-protected `PAGE_READWRITE \| PAGE_GUARD`, with a vectored exception handler filtering `STATUS_GUARD_PAGE_VIOLATION` |
| canary       | a second page holding the ASCII marker `POKE1337`, checked for intactness                                                                                      |

Reading the guarded page raises a first-chance exception the client catches; overwriting the canary destroys the marker. Either one sets a bit that ships in the next report. The read-and-clear that consumes the flag is gated by control bit `0x04`, so if the server does not ask for it the hit stays latched for a later scan. Arming itself happens only once per process.

### The client's own file

The "self" hash and signature cover the running executable, resolved with `GetModuleFileNameW(NULL)`. Both are computed once per process behind thread-safe once-guards — one per cached value — not once per scan.

### The server chooses how much runs

The `0x638` payload is a `u8` gate byte, two `u32`s, then a `u8` control byte. The `u32`s are carried through to the reply verbatim and never interpreted; the control byte sets the depth of the scan:

| Bit    | Effect                                      |
| ------ | ------------------------------------------- |
| `0x01` | run the handle-table enumeration at all     |
| `0x02` | run the `POKE1337` canary check             |
| `0x04` | report and clear the tripwire flag          |
| `0x08` | compute the client's own hash and signature |

So a scan can be a bare enumeration with no tripwire reporting, or a tripwire read on its own with no enumeration.

### No dynamic observation yet

The 2026-09-15 build has not been instrumented. The ~1 h / 9-session Frida tracing in §2 was captured on the 2026-08-23 build — four builds before `0x638` existed — so it says nothing about this component. From the disassembly alone: it does not run at startup, on a timer, or on connect, and nothing happens unless the server sends `0x638`.


## 4. Hardware Fingerprinting

A collector cluster around `0x140751000–0x140754000`:

| Function        | API / source                                                                             | Output               |
| --------------- | ---------------------------------------------------------------------------------------- | -------------------- |
| `FUN_140752830` | `GetAdaptersInfo` — MAC bytes at struct `+0x199..+0x19f`                                 | hex MAC string(s)    |
| `FUN_140753150` | `GetSystemFirmwareTable('RSMB')`                                                         | raw SMBIOS tables    |
| `FUN_1407535b0` | `CreateFileA("\\\\.\\PhysicalDrive0")` + `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` | physical disk serial |
| `FUN_140752b40` | `RegOpenKeyExA(HKLM\SOFTWARE\Microsoft\Cryptography)` → `MachineGuid`                    | MachineGuid          |
| `FUN_140752280` | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString`                | CPU model            |
| `FUN_140752aa0` | `GetUserNameA`                                                                           | Windows username     |
| `FUN_1407523a0` | `GlobalMemoryStatusEx`                                                                   | total RAM            |

`getHWID` (`FUN_140753b50`) concatenates MachineGuid + SMBIOS + disk serial into one `u:` / `d:` / `g:`-prefixed identifier, exposed to Lua as `g_platform.getHWID`.

The sender (`FUN_140468ee0`) writes **client→server opcode `0x000A`** and appends: machine identifier, Windows username, CPU model, total RAM, MAC list, combined HWID, and the OTCv8 client-id string. It emits the Lua signal `getLoginExtendedData` first so modules can append fields, then transmits.

It fires on **every game connection** (ProtocolGame connect path) and again whenever the server sends **opcode `0x1F`** — a mid-session re-request. Dynamic tracing shows this happening at the login screen, before character select.


## 5. Local Blacklists — Removed From `init.lua`

Four plaintext globals, which shipped in the (encrypted) `init.lua` up to the 2026-08-28 build:

```lua
DLL_CHECKSUM   = { {"d3dcompiler_47.dll","d30621d9"}, {"libEGL.dll","792836ce"}, {"libGLESv2.dll","9b805101"} }
BAD_FILES      = {"lam", "engine.spr", "LanEngine.key", "LanEngine.dll", "opengl32.dll"}
BAD_PROCESSES  = {"NinjaRipper.exe", "injhelper.exe", "ripdump.exe"}
BAD_DLLS       = {"intruder.dll", "d3dx8d.dll", "d3dwrap.dll"}
```

They are byte-identical in every build that still carries them, from 2026-08-07 through 2026-08-28 — the list has never been updated. **In the 2026-09-09 build nothing reads them**, and by the 2026-09-15 build they are absent from `init.lua`.

On the 2026-08-28 build each of the four names existed as a string literal with exactly one code reference, all four inside the startup scanner `FUN_1407c7cc0`, which re-used the §2 collectors to run four checks (per-DLL digest, file existence, process `std::find`, module `std::find`) and was wired to the terminator. In the 2026-09-09 binary that whole path is gone:

- `BAD_FILES`, `BAD_DLLS`, `BAD_PROCESSES` and `DLL_CHECKSUM` have **zero byte occurrences** — ASCII and UTF-16 alike. So does the scanner's `"not clean"` evaluator string. A Lua-global read cannot be compiled without the literal name.
- `CreateToolhelp32Snapshot`, `EnumProcessModules` and `EnumWindows` are each called from **exactly one** address, the opcode handler from §2. Nothing builds a process, module or window list outside a server request.
- The terminator `PostMessageA(hwnd, 0x10 /* WM_CLOSE */, 0, 0)` still exists (`FUN_1405147c0`), but its only caller is the application bootstrap `FUN_1407c6fb0` — the startup teardown that posts to a not-yet-populated window handle. No violation check reaches it.
- No alternative enumeration API is imported — `NtQuerySystemInformation`, `WTSEnumerateProcessesW`, `EnumProcesses` and `QueryFullProcessImageNameA/W` are all absent from the import table.

Two related Lua bindings went with it: `g_resources.selfChecksum` and `g_resources.filesChecksums` no longer appear in the client's `g_resources` registration table (`fileChecksum`, `isEncrypted` and `updateExecutable` survive), although the shipped `updater.lua` still calls both.

On the 2026-09-09 build the client performs **no local checks at all**. The `init.lua` blacklist is inert data. Nothing on it is modern anyway — no Frida, Cheat Engine, x64dbg, ReClass, IDA, Process Hacker, Wireshark, AutoIt or AHK, no overlays, and not `dbghelp`; `d3dx8d.dll` / `d3dwrap.dll` / `intruder.dll` are mid-2000s DirectX-8-wrapper-era tooling.

On the 2026-09-15 build the four literals remain absent from the binary, but two of the bullets above no longer hold, because the new component (§3) brings back both enumeration primitives. `NtQuerySystemInformation` is still absent from the import table, but the name is present as a string and resolved with `GetProcAddress`, and `QueryFullProcessImageNameW` is imported outright.

## 6. The Bot-Protection Gate

`FUN_1402d0c30`, registered as Lua binding `g_game.checkBotProtection`. It cancels a call to a protected `g_game` function when the game-object feature bit `0x800000000` at `+0x238` is set, the in-game flag at `+0x16a` is set, and the call originated from Lua, then logs:

```
caught a lua call to a bot protected game function, the call was cancelled
```

An earlier reading assumed the additional guard bytes were a server-driven "arm" flag. They are not: one is the generic Lua→C call-nesting counter (incremented and decremented around every C-closure dispatch), one is a `GraphicalApplication` field zeroed in the app constructor and never written again, and one is never written at all. **Nothing server-side arms this gate** — arming is the feature bit, which arrives with the game-feature set. The whole mechanism is inherited from stock OTClient.


## 7. What Was Searched For and NOT Found

| Technique                                                                                                                                                       | Search method                                              | Result                                                                                                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CheckRemoteDebuggerPresent`                                                                                                                                    | Import table + strings                                     | Absent                                                                                                                                                                                                 |
| `NtQueryInformationProcess`                                                                                                                                     | Imports + strings                                          | Absent                                                                                                                                                                                                 |
| `NtSetInformationThread` (ThreadHideFromDebugger)                                                                                                               | Imports + strings                                          | Absent                                                                                                                                                                                                 |
| PEB `BeingDebugged` / `NtGlobalFlag`                                                                                                                            | Byte patterns (`65 48 8b 04 25 60 00 00 00` = `gs:[0x60]`) | Zero matches                                                                                                                                                                                           |
| `IsDebuggerPresent` in game logic                                                                                                                               | All 40 IAT refs                                            | All in the CRT range `0x1415C9CA7–0x1415F62CD`, error handling only                                                                                                                                    |
| RDTSC delta trap                                                                                                                                                | Decompilation of every `0F 31` site                        | None — all in OpenSSL capability asm or decoding artifacts                                                                                                                                             |
| `INT3` (0xCC) scan over `.text`                                                                                                                                 | Byte pattern scan                                          | Absent                                                                                                                                                                                                 |
| `.text` CRC / self-integrity loop                                                                                                                               | Accumulation-loop patterns                                 | Absent — the updater's own file hashing is the only hashing in the client, and it is not self-integrity (§5)                                                                                           |
| IAT / inline hook detection                                                                                                                                     | Module enumeration scan                                    | Absent                                                                                                                                                                                                 |
| VM / sandbox detection                                                                                                                                          | String scan + device probes                                | Absent — only FFmpeg codec-table literals                                                                                                                                                              |
| `ReadProcessMemory`, `WriteProcessMemory`, `CreateRemoteThread`, `SetWindowsHookEx`, `GetAsyncKeyState`, `Thread32First/Next`                                   | Import table                                               | **Absent from the import table entirely**                                                                                                                                                              |
| `OpenProcess`, `QueryFullProcessImageNameW`, `CreateFileW`, `BCrypt*`, `WinVerifyTrust`, `CryptQueryObject`, `CertFindCertificateInStore`, `CertGetNameStringW` | Import table                                               | **Present as of 2026-09-15** — the scanner in §3 opens other processes read-only, resolves their image paths, hashes their files and verifies their signatures. It does not read or write their memory |
| `AddVectoredExceptionHandler`                                                                                                                                   | Import table                                               | **Present as of 2026-09-15** — used by the tripwire in §3                                                                                                                                              |
| Self-modifying code                                                                                                                                             | `VirtualProtect` / `VirtualQuery` sites                    | All in CRT / CFG support range, except the `PAGE_GUARD` re-protection in §3                                                                                                                            |
| `CPUID`                                                                                                                                                         | —                                                          | Only in OpenSSL capability detection                                                                                                                                                                   |
| Screenshot exfiltration                                                                                                                                         | `doScreenshot` XREFs                                       | Plain user-facing feature, no network use                                                                                                                                                              |


## 8. Conclusion

PokeAlliance defends itself in exactly one place: **the server**. The client is an informant, not a guard.

- It has **no anti-analysis**: no anti-debugging, no anti-hooking, no code-integrity check, no driver, no watchdog. A debugger can be attached and the process stays stable.
- It has **one piece of self-defence**, added in 2026-09-15: a memory tripwire (§3) that notices if its own tagged pages are read or overwritten, and reports it on the next scan. It detects but does not defend — it stops nothing, and it only fires if the server has already sent `0x638` once in that session.
- It has **extensive reporting**: full hardware fingerprint at login and on demand (`0x1F`), on-demand process / module / window inventories (`0x50` / `0x51` / `0x52`) that expose any injected DLL, cheat-tool window or debug agent, and since 2026-09-15 a handle-table scan (`0x638`) that reports the path, SHA-256 and Authenticode signer of every process holding a memory-capable handle to the client.
- Its **local** enforcement is gone — the blacklist was last updated in 2026-08-07, no client code has read it since 2026-09-09, and the 2026-09-15 `init.lua` no longer ships it. The 2026-09-15 scanner is not a blacklist: it matches nothing against a list, it reports raw evidence.
- Its **server-side** verdict logic is not observable from the binary.
- The `0x50` / `0x51` / `0x52` reporters are **dormant in practice**: neither ordinary play nor ~1 hour of instrumented tracing produced a server trigger. The collector itself was exercised out-of-band to capture a baseline, so the code path is known good — what is missing is the server's request. The most plausible trigger is sustained repetitive behaviour scored over a long session, not any single action. **`0x638` has never been tested dynamically** — the tracing predates it.

## Appendix — Addresses (base `0x140000000`)

Shift on every recompile, and not by a constant amount — the 2026-08-28 revision of these tables differs from 2026-09-09 by `0x1900`–`0x6000` depending on the section. Each table below is from the build named above it.


### 2026-09-15 build

| Role                                                               | Address                                                       |
| ------------------------------------------------------------------ | ------------------------------------------------------------- |
| Anti-cheat handler `ProtocolGame::parseAntiCheat` (opcode `0x638`) | `FUN_140463b40`                                               |
| `ProtocolGame::onRecv` / packet dispatcher                         | `FUN_140418120` / `FUN_140418e10`                             |
| Custom-opcode jump table (`0x5DD–0x639`, 0x5D entries)             | `0x14041af30`                                                 |
| `0x638` case / call to the handler                                 | `0x14041a95c` / `0x14041a962`                                 |
| `0x639` handler (pinned-text UI)                                   | `FUN_1404639c0`                                               |
| `0x50` / `0x51` / `0x52` collectors                                | `FUN_1407570c0` / `FUN_140756e80` / `FUN_140757450`           |
| `0x51` / `0x52` handlers                                           | `FUN_1404461a0` / `FUN_140446310`                             |
| `EnumWindows` callback (`GetWindowTextA`)                          | `FUN_1407572c0`                                               |
| Handle-table scanner (the queued task)                             | `FUN_1404b0ee0`                                               |
| `NtQuerySystemInformation` call site (class `0x40`)                | `0x1404b12d5`                                                 |
| Control-byte read in the scanner                                   | `0x1404b0f24`                                                 |
| `SeDebugPrivilege` enablement                                      | `0x1404b1100`                                                 |
| PID → image path resolver                                          | `FUN_140749460`                                               |
| File hash (SHA-256)                                                | `FUN_1407495a0`                                               |
| Signature verification (`WinVerifyTrust` + certificate chain)      | `FUN_1407499c0`                                               |
| UTF-16 → UTF-8 conversion                                          | `FUN_140749230`                                               |
| Self-path resolver (`GetModuleFileNameW`)                          | `FUN_140749390`                                               |
| Self hash / signer name / signature-valid byte                     | `0x1437469a8` / `0x143746988` / `0x1437469d4`                 |
| Once-guard statics (one per cached value)                          | `0x1437469d0` / `0x143746980` / `0x14374695c` / `0x1437469d8` |
| Reply builder (sends opcode `0x638`)                               | `FUN_1404a4bb0`                                               |
| Tripwire vectored exception handler                                | `0x140749190`                                                 |
| Guarded page / canary page                                         | `0x143740878` / `0x143740938`                                 |
| Tripwire flag                                                      | `0x14373e038`                                                 |
| Report scheduler                                                   | `0x14373ed90`                                                 |


### 2026-09-09 build

The `BAD_*` / `DLL_CHECKSUM` scanner and its `std::find` matcher, and the `selfChecksum` / `filesChecksums` bindings, no longer exist in this build (§5).

| Role                                                   | Address                                    |
| ------------------------------------------------------ | ------------------------------------------ |
| Game-packet dispatcher                                 | `FUN_140417670`                            |
| Custom-opcode jump table (`0x5DD–0x637`, 0x5B entries) | `0x14041979C`                              |
| Second dispatch table (`0x51–0x11D`, 0xCD entries)     | `0x140419468`                              |
| `parseGameServerCheckBot` (opcode `0x5EA`)             | `FUN_14042b5a0`                            |
| `0x50` handler / process collector                     | `FUN_140417670` (inline) / `FUN_140754440` |
| `0x51` handler / module collector                      | `FUN_140444210` / `FUN_140754200`          |
| `0x52` handler / window collector                      | `FUN_140444380` / `FUN_1407547d0`          |
| Login extended-data sender (opcode `0x000A`)           | `FUN_140468ee0`                            |
| MAC collector (`GetAdaptersInfo`)                      | `FUN_140752830`                            |
| SMBIOS reader (`GetSystemFirmwareTable`)               | `FUN_140753150`                            |
| Disk serial reader (`PhysicalDrive0`)                  | `FUN_1407535b0`                            |
| `MachineGuid` registry reader                          | `FUN_140752b40`                            |
| CPU name reader                                        | `FUN_140752280`                            |
| `GetUserNameA` wrapper                                 | `FUN_140752aa0`                            |
| `getHWID` combiner                                     | `FUN_140753b50`                            |
| `FindWindowA` wrapper (`isProcessRunning`)             | `FUN_140751740`                            |
| Terminator (`PostMessageA(WM_CLOSE)`)                  | `FUN_1405147c0`                            |
| `checkBotProtection` guard                             | `FUN_1402d0c30`                            |
| Application bootstrap                                  | `FUN_1407c6fb0`                            |

