# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Tables of dangerous Python calls, and helpers to name a call.

A "sink" is a call where untrusted input can do damage, for example
`subprocess.run(user_text, shell=True)`.
"""

from __future__ import annotations

import ast

from mcp_scanner.analyzers.source import facts as f

COMMAND_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execlp",
    "os.spawnl",
    "os.spawnv",
    "os.spawnvp",
    "os.posix_spawn",
    "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
    "pty.spawn",
    "commands.getoutput",
}
SHELL_ALWAYS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell",
    "commands.getoutput",
}
# compile() only checks and builds code. Running it needs exec() or eval(), which are caught
# through taint, so compile() itself is not a sink.
EVAL_SINKS = {"eval", "exec", "builtins.eval", "builtins.exec", "runpy.run_path", "runpy.run_module"}
# Path methods that share a name with str methods.
STRING_LOOKALIKES = {"replace", "rename"}
IMPORT_SINKS = {"__import__", "importlib.import_module"}
DESERIALIZE_SINKS = {
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "shelve.open",
    "jsonpickle.decode",
    "yaml.unsafe_load",
    "pandas.read_pickle",
    "joblib.load",
}
DECODERS = {
    "base64.b64decode",
    "base64.b32decode",
    "base64.b16decode",
    "base64.decodebytes",
    "codecs.decode",
    "zlib.decompress",
    "bytes.fromhex",
    "marshal.loads",
    "gzip.decompress",
    "lzma.decompress",
    "bz2.decompress",
}
OPEN_CALLS = {"open", "io.open", "os.open", "codecs.open"}
DELETE_OR_MOVE = {
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copy2",
    "shutil.copytree",
    "os.rename",
    "os.replace",
    "os.chmod",
    "os.chown",
}
LIST_CALLS = {"os.listdir", "os.scandir", "os.walk", "glob.glob", "glob.iglob"}
PATH_WRITE_METHODS = {
    "write_text",
    "write_bytes",
    "unlink",
    "rmdir",
    "rename",
    "replace",
    "touch",
    "mkdir",
    "chmod",
    "symlink_to",
}
PATH_READ_METHODS = {"read_text", "read_bytes", "iterdir", "glob", "rglob"}
NETWORK_SINKS = {
    f"{lib}.{verb}"
    for lib in ("requests", "httpx")
    for verb in ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")
} | {
    "urllib.request.urlopen",
    "urllib.request.Request",
    "urllib.urlopen",
    "urllib2.urlopen",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "socket.create_connection",
    "aiohttp.request",
}
CLIENT_NAME_HINTS = ("session", "client", "http")
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "mogrify"}
TEMPLATE_SINKS = {
    "jinja2.Template",
    "Template",
    "mako.template.Template",
    "flask.render_template_string",
    "render_template_string",
    "jinja2.Environment.from_string",
}
SANITIZERS = {
    "shlex.quote",
    "pipes.quote",
    "int",
    "float",
    "bool",
    "len",
    "os.path.basename",
    "re.escape",
    "html.escape",
    "markupsafe.escape",
    "urllib.parse.quote",
    "quote",
    "str.isdigit",
    "hash",
    "hashlib.sha256",
}


def dotted_name(node: ast.AST) -> str | None:
    """`subprocess.run` -> "subprocess.run"; `self.helper` -> "self.helper"."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return None


def resolve(name: str | None, aliases: dict[str, str]) -> str | None:
    """Undo import aliases: with `import subprocess as sp`, `sp.run` becomes `subprocess.run`."""
    if not name:
        return None
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + (f".{rest}" if rest else "")
    return name


def kwarg(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def first_arg(call: ast.Call) -> ast.expr | None:
    return call.args[0] if call.args else None


def open_mode(call: ast.Call) -> str:
    mode = call.args[1] if len(call.args) > 1 else kwarg(call, "mode")
    return mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else "r"


def is_unsafe_yaml(call: ast.Call, name: str) -> bool:
    if name != "yaml.load":
        return False
    loader = kwarg(call, "Loader") or (call.args[1] if len(call.args) > 1 else None)
    loader_name = dotted_name(loader) if loader is not None else ""
    return not (loader_name and "Safe" in loader_name)


def is_unsafe_torch(call: ast.Call, name: str) -> bool:
    return name == "torch.load" and not is_true(kwarg(call, "weights_only"))


def categorize(call: ast.Call, name: str) -> tuple[str, str] | None:
    """Return (category, detail) for a dangerous call, or None."""
    if name in COMMAND_SINKS:
        shell = name in SHELL_ALWAYS or is_true(kwarg(call, "shell"))
        return f.COMMAND, "runs through a shell" if shell else "runs a program"
    if name in EVAL_SINKS:
        return f.CODE_EVAL, f"{name}()"
    if name in DESERIALIZE_SINKS or is_unsafe_yaml(call, name) or is_unsafe_torch(call, name):
        return f.DESERIALIZATION, f"{name}()"
    if name in OPEN_CALLS:
        mode = open_mode(call)
        return (f.FILE_WRITE, f"open(mode='{mode}')") if any(c in mode for c in "wax+") else (f.FILE_READ, "open()")
    if name in DELETE_OR_MOVE:
        return f.FILE_WRITE, f"{name}()"
    if name in LIST_CALLS:
        return f.FILE_READ, f"{name}()"
    if name in NETWORK_SINKS:
        return f.NETWORK, f"{name}()"
    if name in TEMPLATE_SINKS or name.endswith(".from_string"):
        return f.TEMPLATE, f"{name}()"
    method = name.rpartition(".")[2]
    if method in STRING_LOOKALIKES and (len(call.args) != 1 or call.keywords):
        # str.replace(old, new) is text work, and datetime.replace(tzinfo=...) is date work.
        # Path.replace(target) and Path.rename(target) take exactly one positional argument.
        return None
    return _method_category(name)


def _method_category(name: str) -> tuple[str, str] | None:
    head, _, method = name.rpartition(".")
    if not head:
        return None
    if method in PATH_WRITE_METHODS:
        return f.FILE_WRITE, f".{method}()"
    if method in PATH_READ_METHODS:
        return f.FILE_READ, f".{method}()"
    if method in SQL_METHODS and any(h in head.lower() for h in ("cursor", "conn", "db", "session", "engine", "cur")):
        return f.SQL, f".{method}()"
    if method in ("get", "post", "put", "patch", "delete", "request", "stream") and any(
        h in head.lower().rsplit(".", 1)[-1] for h in CLIENT_NAME_HINTS
    ):
        return f.NETWORK, f".{method}()"
    return None
