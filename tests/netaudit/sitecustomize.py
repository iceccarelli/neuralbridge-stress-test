"""Independent network/process observer, loaded into the product's subprocess.

A permanent ``sys.addaudithook`` records every socket and process-spawn event that reaches
the interpreter and appends it to the file named by ``NB_NET_LOG``. It is independent of the
product's own air-gap guard: it does not read that guard's record, so it cannot be fooled by
it, and a hook cannot be removed once added. Events the product's guard refuses before the
socket layer never fire; what is recorded here is what actually got through.
"""
import json
import os
import sys

_LOG = os.environ.get("NB_NET_LOG")
_WATCH = {
    "socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
}


def _hook(event, args):
    if _LOG and event in _WATCH:
        try:
            with open(_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"event": event, "args": repr(args)[:200]}) + "\n")
        except OSError:
            pass


if _LOG:
    sys.addaudithook(_hook)
