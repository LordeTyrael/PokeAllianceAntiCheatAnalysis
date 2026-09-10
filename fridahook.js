const GHIDRA_BASE = ptr('0x140000000');
const BLOCK_KILL = false; // true => neutralize self-termination

const OFFS = {
    OUTMSG_CTOR:    0x14046d620, // OutputMessage ctor
    ADD_U8:         0x14041ac40, // addU8 — opcode writer seen in all senders
    SEND_PROC:      0x1404474f0, // reply 0x50 process list
    SEND_MOD:       0x140447660, // reply 0x51 module list
    SEND_WND:       0x1404477d0, // reply 0x52 window titles
    FP_SENDER:      0x14046a800, // login extended data / opcode 0x000A
    CHECKBOT_PARSE: 0x14042edb0, // parseGameServerCheckBot
    PROC_LISTER:    0x140752f20, // Toolhelp32 process enumerator
    MOD_LISTER:     0x140752ce0, // EnumProcessModules enumerator
    WND_COLLECTOR:  0x1407532b0, // EnumWindows collector
    HWID_COMBINER:  0x1407526c0, // getHWID (smbios+disk+machineguid)
    MAC_COLL:       0x1407518f0, // GetAdaptersInfo MACs
    SMBIOS:         0x140751d50, // GetSystemFirmwareTable RSMB
    DISK_SERIAL:    0x140752430, // PhysicalDrive0 IOCTL
    MACHINEGUID:    0x140751c00, // Cryptography\MachineGuid
    TERMINATOR:     0x140516740, // PostMessageA(hwnd, WM_CLOSE)
    BOT_GUARD:      0x1402daae0, // checkBotProtection native guard
    EVALUATOR:      0x1407c50e0, // clean/dirty evaluator (wraps orchestrator)
    MONITOR_THREAD: 0x1407c6ec0, // _beginthreadex worker from FUN_1407c5160
    DISPATCHER:     0x14041bd00, // main server->client packet dispatcher
    GET_U8:         0x1407334c0, // InputMessage::getU8
    GET_U16:        0x140733530, // InputMessage::getU16
};

let modBase = null;
function A(ghidraVa) {
    if (modBase === null) {
        const m = Process.getModuleByName('PokeAlliance_dx.exe');
        modBase = m.base;
        send(`[INIT] module base = ${modBase}`);
    }
    return modBase.add(ghidraVa - 0x140000000);
}

function ts() { return new Date().toISOString().slice(11, 23); }

function tag(addrNum) {
    for (const [name, off] of Object.entries(OFFS)) {
        if (off === addrNum) return name;
    }
    return 'sub_' + (addrNum >>> 0).toString(16);
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.FUZZY)
        .slice(0, 12)
        .map(a => {
            const m = Process.findModuleByAddress(a);
            const rel = m ? `${m.name}+0x${a.sub(m.base).toString(16)}` : a.toString();
            // translate back to ghidra VA when it's our module
            let gva = '';
            if (m && m.name === 'PokeAlliance_dx.exe') {
                gva = ` (VA 0x${GHIDRA_BASE.add(a.sub(modBase)).toString(16)})`;
            }
            return `    ${rel}${gva}`;
        }).join('\n');
}

function hook(name, opts) {
    const target = A(OFFS[name]);
    try {
        Interceptor.attach(target, opts);
        send(`[HOOK] ${name} @ ${target}`);
    } catch (e) {
        send(`[ERROR] hook ${name}: ${e}`);
    }
}

let msgCounter = 0;
const msgIds = new Map(); // msg object -> id (weak-ish; bounded cleanup)

hook('OUTMSG_CTOR', {
    onEnter(args) { this.slot = args[0]; },
    onLeave() {
        const id = ++msgCounter;
        try {
            const obj = this.slot.readPointer();
            msgIds.set(obj.toString(), id);
        } catch (e) { return; }
        send(`[MSG][${ts()}] #${id} OutputMessage created`);
        if (msgIds.size > 4096) msgIds.clear();
    }
});

hook('ADD_U8', {
    onEnter(args) {
        const id = msgIds.get(args[0].toString());
        if (id !== undefined) {
            const v = args[1].toInt32() & 0xff;
            // first u8 written into a fresh message is its opcode
            const known = {0x50: 'PROCESS_LIST', 0x51: 'MODULE_LIST',
                           0x52: 'WINDOW_LIST', 0x0a: 'FINGERPRINT'};
            const label = known[v] ? ` <== ${known[v]}` : '';
            send(`[MSG][${ts()}] #${id} addU8(0x${v.toString(16).padStart(2,'0')})${label}`);
        }
    }
});

for (const n of ['SEND_PROC', 'SEND_MOD', 'SEND_WND']) {
    hook(n, {
        onEnter() { send(`[SEND][${ts()}] ${n} invoked — server requested inventory`); },
        onLeave() { send(`[SEND][${ts()}] ${n} done`); }
    });
}

hook('FP_SENDER', {
    onEnter(args) {
        send(`[FP][${ts()}] fingerprint sender entered (feature flags arg=0x${args[1].toString(16)}, ${args[2]})\n${bt(this.context)}`);
    }
});

for (const n of ['HWID_COMBINER', 'MAC_COLL', 'SMBIOS', 'DISK_SERIAL', 'MACHINEGUID']) {
    hook(n, { onEnter() { send(`[FP][${ts()}] collect ${n}`); } });
}

hook('CHECKBOT_PARSE', {
    onEnter() { send(`[BOT][${ts()}] parseGameServerCheckBot fired (server sent CheckBot challenge)`); }
});

hook('PROC_LISTER', {
    onEnter(args) {
        // also called directly by the blacklist orchestrator at startup
        const rt = this.returnAddress;
        const m = Process.findModuleByAddress(rt);
        const gva = (m && m.name === 'PokeAlliance_dx.exe')
            ? ` VA 0x${GHIDRA_BASE.add(rt.sub(modBase)).toString(16)}` : '';
        send(`[ENUM][${ts()}] PROC_LISTER called from ${(m?m.name:'?')}+0x${rt.sub(m?m.base:rt).toString(16)}${gva}`);
    }
});

for (const n of ['MOD_LISTER', 'WND_COLLECTOR']) {
    hook(n, {
        onEnter() {
            const rt = this.returnAddress;
            const m = Process.findModuleByAddress(rt);
            const gva = (m && m.name === 'PokeAlliance_dx.exe')
                ? ` VA 0x${GHIDRA_BASE.add(rt.sub(modBase)).toString(16)}` : '';
            send(`[ENUM][${ts()}] ${n} called from ${(m ? m.name : '?')}+0x${rt.sub(m ? m.base : rt).toString(16)}${gva}`);
        }
    });
}

hook('TERMINATOR', {
    onEnter() {
        send(`[KILL][${ts()}] *** SELF-TERMINATION FIRED (WM_CLOSE) ***\n${bt(this.context)}`);
        if (BLOCK_KILL) {
            // replace with immediate return: patch onEnter is not enough for
            // PostMessageA call inside; we instead intercept PostMessageA below.
        }
    }
});

try {
    const pm = Module.findGlobalExportByName('PostMessageA')
        || Process.getModuleByName('user32.dll').getExportByName('PostMessageA');
    Interceptor.attach(pm, {
        onEnter(args) {
            const msg = args[1].toInt32();
            if (msg === 0x10 /* WM_CLOSE */ || msg === 0x12 /* WM_QUIT */) {
                send(`[KILL][${ts()}] PostMessageA(hwnd=${args[0]}, msg=0x${msg.toString(16)}, wp=${args[2]}, lp=${args[3]})\n${bt(this.context)}`);
                if (BLOCK_KILL) args[1] = ptr(0); // turn into harmless 0x0 message
            }
        }
    });
    send('[HOOK] user32!PostMessageA watchdog');
} catch (e) { send(`[ERROR] PostMessageA: ${e}`); }

hook('BOT_GUARD', {
    onLeave(ret) {
        send(`[GUARD][${ts()}] checkBotProtection returned ${ret.toInt32()} (${ret.toInt32() ? 'allowed' : 'BLOCKED'})`);
    }
});

hook('EVALUATOR', {
    onLeave(ret) {
        send(`[VERDICT][${ts()}] FUN_1407c50e0 returned ${ret.toInt32()} (${ret.toInt32() ? 'HITS FOUND' : 'no hits'})`);
    }
});

// monitor thread worker — does it rescan periodically?
let monitorHits = 0;
hook('MONITOR_THREAD', {
    onEnter(args) {
        monitorHits++;
        if (monitorHits <= 5 || monitorHits % 50 === 0) {
            send(`[THREAD][${ts()}] MONITOR_THREAD invocation #${monitorHits}\n${bt(this.context)}`);
        }
    }
});

const INTEREST_U16 = new Set([0x1F]);                 // fingerprint re-request
const CUSTOM_LO = 0x5DD, CUSTOM_HI = 0x634;           // custom block incl. 0x5EA CheckBot

const disp = {};   // tid -> {n16, op}
const histo = {};  // "0x.." -> count

hook('DISPATCHER', {
    onEnter() { disp[Process.getCurrentThreadId()] = { n16: 0, op: -1 }; },
});

hook('GET_U16', {
    onLeave(ret) {
        const s = disp[Process.getCurrentThreadId()];
        if (!s) return;
        if (++s.n16 === 1) s.op = ret.toInt32() & 0xffff;
    }
});

hook('DISPATCHER', {
    onLeave() {
        const s = disp[Process.getCurrentThreadId()];
        delete disp[Process.getCurrentThreadId()];
        if (!s || s.n16 === 0) return;
        const key = `0x${s.op.toString(16)}`;
        const hit = INTEREST_U16.has(s.op) || (s.op >= CUSTOM_LO && s.op <= CUSTOM_HI);
        if (hit) {
            send(`[INBOUND][${ts()}] *** SERVER OPCODE ${key} ***` +
                 (s.op === 0x1F ? ' (fingerprint re-request)' :
                  s.op === 0x5EA ? ' (CheckBot challenge!)' : ' (custom block)'));
        } else {
            histo[key] = (histo[key] || 0) + 1;
        }
    }
});

setInterval(() => {
    const keys = Object.keys(histo);
    if (!keys.length) return;
    const summary = keys.map(k => `${k} x${histo[k]}`).join(' ');
    for (const k of keys) delete histo[k];
    send(`[HISTO][${ts()}] inbound opcodes (20s): ${summary}`);
}, 20000);

send('[INIT] agent loaded');

function readCstr(p) {
    try { return p.readCString(); } catch (e) { return null; }
}
function readWstr(p) {
    try { return p.readUtf16String(); } catch (e) { return null; }
}

for (const fn of ['Process32FirstW', 'Process32NextW', 'Process32FirstA', 'Process32NextA']) {
    try {
        const addr = Module.findGlobalExportByName(fn);
        if (!addr) continue;
        const wide = fn.endsWith('W');
        Interceptor.attach(addr, {
            onEnter(args) { this.entry = args[1]; },
            onLeave(ret) {
                if (!ret.toInt32()) return;
                const name = wide ? readWstr(this.entry.add(40)) : readCstr(this.entry.add(40));
                send(`[SCAN][${ts()}] process: ${name}`);
            }
        });
        send(`[HOOK] kernel32!${fn}`);
    } catch (e) { /* variant not present */ }
}

const FRIDA_RE = /frida/i;
const SPOOF_A = 'C:\\Windows\\System32\\KERNEL32.DLL';
for (const fn of ['GetModuleFileNameExA', 'GetModuleFileNameExW', 'GetModuleFileNameA', 'GetModuleFileNameW']) {
    try {
        const addr = Module.findGlobalExportByName(fn);
        if (!addr) continue;
        const wide = fn.endsWith('W');
        Interceptor.attach(addr, {
            onEnter(args) {
                this.buf = wide ? args[2] : args[1];
                this.isEx = fn.includes('Ex'); // Ex: (hProc,hMod,buf,len); plain: (hMod,buf,len)
            },
            onLeave(ret) {
                const len = ret.toInt32();
                if (len <= 0) return;
                let s;
                try { s = wide ? this.buf.readUtf16String() : this.buf.readCString(); } catch (e) { return; }
                if (s) send(`[SCAN][${ts()}] module: ${s}`);
                if (s && FRIDA_RE.test(s)) {
                    if (wide) this.buf.writeUtf16String(SPOOF_A);
                    else this.buf.writeAnsiString(SPOOF_A);
                    ret.replace(SPOOF_A.length);
                    send(`[SPOOF][${ts()}] hid frida module path`);
                }
            }
        });
        send(`[HOOK] ${fn} (frida-spoof active)`);
    } catch (e) { /* not present */ }
}

// DLL file opens during the startup scan (hashing candidates)
try {
    const cf = Module.findGlobalExportByName('CreateFileA')
        || Process.getModuleByName('kernel32.dll').getExportByName('CreateFileA');
    let scanning = true;
    setTimeout(() => { scanning = false; }, 30000); // only care about the startup window
    Interceptor.attach(cf, {
        onEnter(args) {
            const s = readCstr(args[0]);
            if (scanning && s && /\.dll$/i.test(s)) send(`[SCAN][${ts()}] open dll: ${s}`);
        }
    });
    send('[HOOK] kernel32!CreateFileA (.dll filter, first 30s)');
} catch (e) { send(`[ERROR] CreateFileA: ${e}`); }
