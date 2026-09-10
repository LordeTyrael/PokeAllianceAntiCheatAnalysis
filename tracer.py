Usage:
  python tracer.py spawn          # launch client under instrumentation
  python tracer.py attach         # attach to an already-running client
"""
import sys, time, datetime, pathlib
import frida

HERE = pathlib.Path(__file__).parent
EXE = r"C:\PokeAlliance Games\PokeAlliance\PokeAlliance_dx.exe"
TARGET = "PokeAlliance_dx.exe"

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "spawn"
    log_path = HERE / f"trace_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
    log = open(log_path, "w", encoding="utf-8")

    def on_message(message, data):
        if message["type"] == "send":
            line = message["payload"]
        elif message["type"] == "error":
            line = f"[FRIDA-ERR] {message.get('description')}\n{message.get('stack','')}"
        else:
            line = str(message)
        print(line, flush=True)
        log.write(line + "\n")
        log.flush()

    if mode == "spawn":
        pid = frida.spawn([EXE], cwd=str(pathlib.Path(EXE).parent))
        session = frida.attach(pid)
        print(f"[*] spawned pid={pid}")
    else:
        session = frida.attach(TARGET)
        pid = session._impl.pid if hasattr(session, "_impl") else "?"
        print(f"[*] attached to {TARGET}")

    script = session.create_script((HERE / "fridahook.js").read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()

    if mode == "spawn":
        frida.resume(pid)
        print("[*] resumed — client starting")

    print(f"[*] tracing... Ctrl+C to stop. Log: {log_path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("[*] detaching")
        session.detach()

if __name__ == "__main__":
    main()
