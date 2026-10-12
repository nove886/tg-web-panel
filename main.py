#!/usr/bin/env python3
"""Non-interactive Pterodactyl launcher for Telegram WEB proxy.

Python is the panel entry point. The official Go WEB relay is built locally on
first startup; an unmodified Python MTProxy backend supplies Telegram transport.
No Docker, root, system service, Cloudflare API token or Tunnel is used.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / ".runtime"
STOP = threading.Event()
LOG = logging.getLogger("tg-web-panel")
REDACTIONS: set[str] = set()
GO_VERSION = "go1.27.2"
GO_SHA256 = {
    "amd64": "ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5",
    "arm64": "94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8",
}
# Official ranges: https://www.cloudflare.com/ips/ . Only these peers may assert
# CF-Connecting-IP. A local self-check is separately allowed by the front end.
CF_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]


class SetupError(Exception):
    pass


def redact(message: str) -> str:
    message = re.sub(r"(?:https?://t\.me/|tg://)[^\s]+", "[代理链接已隐藏]", message)
    message = re.sub(r"(?i)(secret[=:]\s*)[^\s,]+", r"\1[已隐藏]", message)
    for value in sorted(REDACTIONS, key=len, reverse=True):
        if value:
            message = message.replace(value, "[已隐藏]")
    return message


def init_logging():
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    LOG.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    file = logging.handlers.RotatingFileHandler(
        RUNTIME / "launcher.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8"
    )
    file.setFormatter(formatter)
    LOG.handlers[:] = [stream, file]


def private_write(path: Path, data: str | bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            os.chmod(temporary, 0o600)
            file.write(data.encode("utf-8") if isinstance(data, str) else data)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, value):
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise SetupError(f"找不到配置文件：{path.name}") from exc
    except json.JSONDecodeError as exc:
        raise SetupError(f"{path.name} 第 {exc.lineno} 行 JSON 格式错误：{exc.msg}") from exc


def port_number(value, name: str, allow_zero=False) -> int:
    if isinstance(value, bool) or not re.fullmatch(r"\d+", str(value)):
        raise SetupError(f"{name} 必须是整数端口")
    port = int(value)
    if not ((0 if allow_zero else 1) <= port <= 65535):
        raise SetupError(f"{name} 必须在 1–65535 之间")
    return port


def load_config(path: Path, environ=None) -> dict:
    env = os.environ if environ is None else environ
    c = read_json(path)
    if not isinstance(c, dict):
        raise SetupError("config.json 最外层必须是对象")
    allowed = {"domain", "listen_port", "secret", "carrier_mode", "tls",
               "install_python_dependencies", "check_public_entry", "show_link_in_console"}
    if extra := set(c) - allowed:
        raise SetupError("未知配置项：" + ", ".join(sorted(extra)))
    domain = c.get("domain", "")
    if not isinstance(domain, str):
        raise SetupError("domain 必须是域名字符串")
    domain = domain.strip().lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SetupError("domain 不是合法域名") from exc
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(domain) > 253 or not re.fullmatch(label + r"(?:\." + label + r")+", domain):
        raise SetupError("domain 只填域名，不带 https://、端口、路径；例如 tg.example.net")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise SetupError("WEB 模式要求域名，不能填写 IP 地址")
    if domain == "tg.your-domain.com" or domain.endswith(".example.com"):
        raise SetupError("请先在 config.json 中把 domain 改成你自己的域名")
    c["domain"] = domain
    port = port_number(c.get("listen_port", 0), "listen_port", allow_zero=True)
    if not port:
        raw = env.get("SERVER_PORT") or env.get("PORT")
        if not raw:
            raise SetupError("面板未提供 SERVER_PORT/PORT；请在 listen_port 填面板分配的内部监听端口")
        port = port_number(raw, "面板环境变量端口")
    c["listen_port"] = port
    secret = c.get("secret", "")
    if not isinstance(secret, str) or (secret and not re.fullmatch(r"(?:dd)?[0-9a-fA-F]{32}", secret)):
        raise SetupError("secret 留空自动生成，或填写 32 位十六进制；也支持 dd 加 32 位")
    c["secret"] = secret.lower()
    carrier = c.get("carrier_mode", "websocket")
    if carrier not in {"https", "https-lanes", "websocket", "websocket-lanes"}:
        raise SetupError("carrier_mode 应为 websocket、websocket-lanes、https 或 https-lanes")
    c["carrier_mode"] = carrier
    tls = c.get("tls", {"mode": "self_signed"})
    if not isinstance(tls, dict) or set(tls) - {"mode", "cert_file", "key_file"}:
        raise SetupError("tls 只接受 mode、cert_file、key_file")
    if tls.get("mode") not in {"self_signed", "provided"}:
        raise SetupError("tls.mode 应为 self_signed 或 provided")
    if tls["mode"] == "provided":
        for key in ("cert_file", "key_file"):
            value = tls.get(key)
            if not isinstance(value, str) or not value:
                raise SetupError(f"tls.{key} 必须填写上传的 PEM 文件名")
            p = (ROOT / value).resolve()
            if not p.is_file():
                raise SetupError(f"找不到 tls.{key} 指定的文件")
            tls[key] = str(p)
    c["tls"] = tls
    for name, default in [("install_python_dependencies", True),
                          ("check_public_entry", True), ("show_link_in_console", False)]:
        value = c.get(name, default)
        if not isinstance(value, bool):
            raise SetupError(f"{name} 必须是 true 或 false")
        c[name] = value
    return c


def ensure_secret(c: dict) -> str:
    path = RUNTIME / "generated-secret.txt"
    if c["secret"]:
        value = c["secret"]
    elif path.exists():
        value = path.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            raise SetupError("已保存的密钥损坏；请在 config.json 中明确填写有效 secret")
    else:
        value = secrets.token_hex(16)
        private_write(path, value + "\n")
    REDACTIONS.update({value, value[-32:]})
    return value


def remove_runtime_tree(path: Path):
    # Only staging/cache directories owned by this launcher may be removed.
    resolved = path.resolve()
    if resolved == RUNTIME.resolve() or RUNTIME.resolve() not in resolved.parents:
        raise SetupError("拒绝清理运行目录以外的路径")
    if path.is_symlink():
        raise SetupError("拒绝清理符号链接目录")
    if path.exists():
        shutil.rmtree(path)


def download(url: str, target: Path, *, expected_hash=None, limit=160_000_000):
    if not url.startswith("https://"):
        raise SetupError("组件下载只接受 HTTPS")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".part")
    for attempt in range(3):
        if STOP.is_set():
            raise KeyboardInterrupt
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "tg-web-panel/1.0"})
            digest = hashlib.sha256()
            size = 0
            last_notice = time.monotonic()
            deadline = last_notice + 600
            with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as out:
                if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                    raise SetupError("组件下载被重定向到非 HTTPS 地址")
                while block := response.read(256 * 1024):
                    if STOP.is_set():
                        raise KeyboardInterrupt
                    if time.monotonic() > deadline:
                        raise TimeoutError("下载超时")
                    size += len(block)
                    if size > limit:
                        raise SetupError("下载内容超过预期大小上限")
                    digest.update(block)
                    out.write(block)
                    if time.monotonic() - last_notice > 15:
                        LOG.info("下载中：%s，%.1f MiB", target.name, size / 1024**2)
                        last_notice = time.monotonic()
            if expected_hash and not secrets.compare_digest(digest.hexdigest(), expected_hash):
                raise SetupError("组件 SHA-256 校验失败：" + target.name)
            os.replace(temporary, target)
            return digest.hexdigest()
        except (OSError, urllib.error.URLError) as exc:
            if attempt == 2:
                raise SetupError("下载失败：" + target.name + "；请检查面板出站网络。" + str(exc)) from exc
            if STOP.wait(2 ** attempt):
                raise KeyboardInterrupt
        finally:
            temporary.unlink(missing_ok=True)


def unpack(archive: Path, destination: Path, max_size=1_000_000_000):
    """Extract regular files/directories only; strip the single archive root."""
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    root = None
    seen = set()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                raise SetupError("压缩包包含非法路径")
            if not path.parts:
                continue
            if root is None:
                root = path.parts[0]
            if path.parts[0] != root:
                raise SetupError("压缩包顶层目录不唯一")
            if not (member.isfile() or member.isdir()):
                raise SetupError("压缩包包含链接或特殊文件")
            if len(path.parts) == 1:
                if member.isfile():
                    raise SetupError("压缩包缺少顶层目录")
                continue
            out = destination.joinpath(*path.parts[1:])
            if destination.resolve() not in out.resolve().parents or out.is_symlink():
                raise SetupError("压缩包路径越界")
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            if out in seen:
                raise SetupError("压缩包包含重复文件")
            seen.add(out)
            total += member.size
            if total > max_size:
                raise SetupError("压缩包解压大小超过上限")
            out.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise SetupError("压缩包文件无法读取")
            with source, out.open("wb") as file:
                shutil.copyfileobj(source, file)
            os.chmod(out, 0o755 if member.mode & 0o111 else 0o644)


def stop_process(process: subprocess.Popen):
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError, OSError):
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, OSError):
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        process.wait(timeout=5)


def start_process(name, args, *, cwd=ROOT, env=None):
    process = subprocess.Popen(
        [str(a) for a in args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", bufsize=1, start_new_session=(os.name == "posix"),
    )
    def consume():
        assert process.stdout is not None
        with process.stdout:
            for line in process.stdout:
                if line.strip():
                    LOG.info("[%s] %s", name, redact(line.rstrip())[:2000])
    threading.Thread(target=consume, daemon=True, name="log-" + name).start()
    return process


def run_command(name, args, *, cwd=ROOT, env=None, timeout=1200):
    process = start_process(name, args, cwd=cwd, env=env)
    deadline = time.monotonic() + timeout
    heartbeat = time.monotonic()
    try:
        while process.poll() is None:
            if STOP.wait(0.5):
                raise KeyboardInterrupt
            if time.monotonic() > deadline:
                raise SetupError(name + " 超时")
            if time.monotonic() - heartbeat > 20:
                LOG.info("%s 仍在执行，请等待……", name)
                heartbeat = time.monotonic()
        if process.returncode:
            raise SetupError(f"{name} 失败，退出码 {process.returncode}，请看上方日志")
    finally:
        stop_process(process)


def get_source(name: str, repo: str, branch: str, lock: dict, lockfile: Path) -> Path:
    record = lock.get(name)
    if record is None:
        LOG.info("首次解析 %s 版本，之后将锁定该版本", name)
        meta = RUNTIME / (name + "-revision.json")
        download(f"https://api.github.com/repos/{repo}/commits/{branch}", meta, limit=5_000_000)
        revision = read_json(meta).get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise SetupError("GitHub 未返回有效提交号：" + name)
        record = {"repository": repo, "revision": revision}
        lock[name] = record
        write_json(lockfile, lock)
    if record.get("repository") != repo or not re.fullmatch(r"[0-9a-f]{40}", record.get("revision", "")):
        raise SetupError("组件版本锁损坏：" + name)
    revision = record["revision"]
    folder = RUNTIME / "sources" / (name + "-" + revision)
    marker = folder / ".panel-unpacked"
    if marker.is_file():
        return folder
    archive = RUNTIME / "downloads" / (name + "-" + revision + ".tar.gz")
    LOG.info("下载 %s 固定版本 %s", name, revision[:12])
    checksum = download(f"https://codeload.github.com/{repo}/tar.gz/{revision}", archive,
                        expected_hash=record.get("archive_sha256"), limit=32_000_000)
    staging = folder.with_name(folder.name + ".staging")
    remove_runtime_tree(staging)
    try:
        unpack(archive, staging, max_size=128_000_000)
        private_write(staging / ".panel-unpacked", revision)
        remove_runtime_tree(folder)
        os.replace(staging, folder)
    finally:
        remove_runtime_tree(staging)
    record["archive_sha256"] = checksum
    write_json(lockfile, lock)
    archive.unlink(missing_ok=True)
    return folder


def prepare_components(c: dict):
    if platform.system() != "Linux":
        raise SetupError("运行包面向 Linux 翼龙面板；本机可用 --check-config 检查配置")
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not arch:
        raise SetupError("目前支持 Linux x86_64 / ARM64")
    lockfile = RUNTIME / "components.lock.json"
    lock = read_json(lockfile) if lockfile.exists() else {}
    if not isinstance(lock, dict):
        raise SetupError("components.lock.json 格式错误")
    tproxy_source = get_source("tproxy", "telegramdesktop/tproxy-server", "master", lock, lockfile)
    mtp_source = get_source("mtproxy", "alexbers/mtprotoproxy", "stable", lock, lockfile)
    bin_dir = RUNTIME / "bin"
    bin_dir.mkdir(exist_ok=True)
    tproxy_bin = bin_dir / "tproxy-server"
    front_bin = bin_dir / "panel-front"
    front_dir = ROOT / "front"
    fingerprint = hashlib.sha256(b"".join(p.read_bytes() for p in sorted(front_dir.glob("*.go")))).hexdigest()
    build_id = {"go": GO_VERSION, "arch": arch, "tproxy": lock["tproxy"]["revision"], "front": fingerprint}
    buildfile = RUNTIME / "build.json"
    built = read_json(buildfile) if buildfile.exists() else None
    if built != build_id or not tproxy_bin.is_file() or not front_bin.is_file():
        go_dir = RUNTIME / "toolchain" / (GO_VERSION + "-" + arch)
        go = go_dir / "bin" / "go"
        if not go.is_file():
            if shutil.disk_usage(RUNTIME).free < 900_000_000:
                raise SetupError("首次编译建议至少留 900 MB 可用磁盘空间")
            archive = RUNTIME / "downloads" / (GO_VERSION + ".tar.gz")
            LOG.info("首次准备 Go 工具链（约 70 MB 下载，仅保存在上传目录内）")
            download(f"https://go.dev/dl/{GO_VERSION}.linux-{arch}.tar.gz", archive,
                     expected_hash=GO_SHA256[arch])
            staging = go_dir.with_name(go_dir.name + ".staging")
            remove_runtime_tree(staging)
            try:
                unpack(archive, staging)
                remove_runtime_tree(go_dir)
                os.replace(staging, go_dir)
            finally:
                remove_runtime_tree(staging)
            archive.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update({"CGO_ENABLED": "0", "GOMAXPROCS": "1", "GOMEMLIMIT": "256MiB",
                    "GOTOOLCHAIN": "local", "GOFLAGS": "-p=1", "GOWORK": "off",
                    "GOCACHE": str(RUNTIME / "go-cache"), "GOMODCACHE": str(RUNTIME / "go-modules")})
        LOG.info("编译官方 WEB 中继；首次启动可能需要数分钟")
        run_command("tproxy-build", [go, "build", "-trimpath", "-o", tproxy_bin, "./cmd/tproxy-server"], cwd=tproxy_source, env=env)
        front_env = dict(env, GO111MODULE="off")
        run_command("front-test", [go, "test", "-count=1", "."], cwd=front_dir, env=front_env)
        run_command("front-build", [go, "build", "-trimpath", "-o", front_bin, "."], cwd=front_dir, env=front_env)
        write_json(buildfile, build_id)
    for executable in (tproxy_bin, front_bin):
        os.chmod(executable, 0o700)
    package_dir = RUNTIME / "python-packages"
    env = os.environ.copy()
    search = [str(package_dir), str(mtp_source)]
    if env.get("PYTHONPATH"):
        search.append(env["PYTHONPATH"])
    env.update({"PYTHONPATH": os.pathsep.join(search), "PYTHONUNBUFFERED": "1"})
    if c["install_python_dependencies"] and not (package_dir / "cryptography").exists() and importlib.util.find_spec("cryptography") is None:
        try:
            run_command("python-deps", [sys.executable, "-m", "pip", "install", "--no-input", "--disable-pip-version-check",
                        "--only-binary=:all:", "--target", package_dir, "-r", ROOT / "requirements.txt"], env=env, timeout=300)
        except SetupError:
            LOG.warning("加速依赖安装失败，将使用后端自带的纯 Python AES，吞吐量会较低")
    return tproxy_bin, front_bin, mtp_source / "mtprotoproxy.py", env


def reserve_internal_ports(excluded: int) -> list[int]:
    sockets = []
    try:
        while len(sockets) < 3:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            if sock.getsockname()[1] == excluded:
                sock.close()
                continue
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def make_runtime_configs(c: dict, secret: str, ports: list[int]):
    backend_port, relay_port, admin_port = ports
    token_path = RUNTIME / "token.key"
    if not token_path.exists():
        private_write(token_path, secrets.token_bytes(32))
    if len(token_path.read_bytes()) != 32:
        raise SetupError("token.key 长度错误；不要随意删除已有凭据，请恢复备份")
    os.chmod(token_path, 0o600)
    profile_path = RUNTIME / "profiles.json"
    write_json(profile_path, {"profiles": [{"name": "panel", "secret": secret,
        "backend": f"127.0.0.1:{backend_port}", "carrier_mode": c["carrier_mode"]}]})
    public_dir = ROOT / "public"
    if not (public_dir / "index.html").is_file():
        raise SetupError("请连同 public/index.html 一起上传；不要把整个工作目录设为网站目录")
    relay = {"public_hostname": c["domain"], "listen": f"127.0.0.1:{relay_port}",
             "admin_listen": f"127.0.0.1:{admin_port}", "public_dir": str(public_dir),
             "static_routes": "exact", "profiles_file": str(profile_path), "token_key_file": str(token_path),
             "limits": {"max_pending_per_session": 8_388_608, "max_pending_global": 67_108_864,
                        "max_sessions_global": 16, "max_streams_global": 256,
                        "max_streams_per_session": 32, "max_backend_dials_in_flight": 32}}
    write_json(RUNTIME / "tproxy.json", relay)
    backend = {"PORT": backend_port, "USERS": {"panel": secret[-32:]},
               "LISTEN_ADDR_IPV4": "127.0.0.1", "LISTEN_ADDR_IPV6": "",
               "MODES": {"classic": not secret.startswith("dd") or len(secret) == 32,
                         "secure": len(secret) == 34, "tls": False},
               "USE_MIDDLE_PROXY": False, "PREFER_IPV6": False, "FAST_MODE": False,
               "MASK": False, "TLS_DOMAIN": c["domain"], "MY_DOMAIN": c["domain"],
               "GET_TIME_PERIOD": 0, "GET_CERT_LEN_PERIOD": 0,
               "STATS_PRINT_PERIOD": 600, "USER_MAX_TCP_CONNS": {"panel": 256}}
    private_write(RUNTIME / "backend.py", "\n".join(f"{key} = {value!r}" for key, value in backend.items()) + "\n")
    tls = c["tls"]
    self_signed = tls["mode"] == "self_signed"
    health = secrets.token_hex(24)
    front = {"domain": c["domain"], "listen": f"0.0.0.0:{c['listen_port']}",
             "target": f"http://127.0.0.1:{relay_port}", "self_signed": self_signed,
             "cert_file": str(RUNTIME / "origin.pem") if self_signed else tls["cert_file"],
             "key_file": str(RUNTIME / "origin.key") if self_signed else tls["key_file"],
             "trusted_cidrs": CF_CIDRS, "health_token": health}
    write_json(RUNTIME / "front.json", front)
    link = "https://t.me/webproxy?" + urllib.parse.urlencode({"server": c["domain"], "secret": secret})
    direct = "tg://webproxy?" + urllib.parse.urlencode({"server": c["domain"], "secret": secret})
    private_write(ROOT / "proxy-link.txt", link + "\n" + direct + "\n")
    if c["show_link_in_console"]:
        print("代理链接（包含访问密钥，请妥善保存）：\n" + link + "\n" + direct, flush=True)
    return health


def wait_listener(process, port, name, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if STOP.is_set():
            raise KeyboardInterrupt
        if process.poll() is not None:
            raise SetupError(f"{name} 在启动期间退出，退出码 {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            STOP.wait(0.3)
    raise SetupError(f"{name} 未能在 {port} 启动；请检查监听权限/端口占用")


def public_probe(domain: str, health: str):
    url = f"https://{domain}/.well-known/panel-check/{health}"
    request = urllib.request.Request(url, headers={"User-Agent": "tg-web-panel-check/1.0", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status == 200 and response.geturl() == url and response.read(256).decode("ascii", "replace") == health
    except (OSError, urllib.error.URLError):
        return False


def supervise(c, components, secret):
    tproxy_bin, front_bin, backend_script, env = components
    ports = reserve_internal_ports(c["listen_port"])
    health = make_runtime_configs(c, secret, ports)
    run_command("配置校验", [tproxy_bin, "-config", RUNTIME / "tproxy.json", "-check"], timeout=30)
    children = []
    try:
        backend = start_process("MTProxy", [sys.executable, "-u", ROOT / "run_backend.py", backend_script, RUNTIME / "backend.py"], env=env)
        children.append(backend)
        wait_listener(backend, ports[0], "Python MTProxy", timeout=60)
        relay = start_process("WEB", [tproxy_bin, "-config", RUNTIME / "tproxy.json"], env=env)
        children.append(relay)
        wait_listener(relay, ports[1], "官方 WEB 中继")
        front = start_process("HTTPS", [front_bin, RUNTIME / "front.json"], env=env)
        children.append(front)
        wait_listener(front, c["listen_port"], "HTTPS 入口")
        LOG.info("本机组件已启动：HTTPS 端口 %s；链接保存在 proxy-link.txt", c["listen_port"])
        LOG.info("Cloudflare：A 记录橙云；回源端口填公网分配端口；SSL 模式 %s",
                 "Full（完全）" if c["tls"]["mode"] == "self_signed" else "Full (strict)，需有效 Origin CA / 公共证书")
        LOG.info("这表示本机就绪，不等于 Telegram 已连接；请用支持 WEB 的客户端验证")
        next_probe = 0.0
        verified = False
        while not STOP.wait(1):
            for child in children:
                if child.poll() is not None:
                    raise SetupError(f"服务子进程退出，退出码 {child.returncode}；将关闭本轮所有组件")
            if c["check_public_entry"] and time.monotonic() >= next_probe:
                reachable = public_probe(c["domain"], health)
                if reachable and not verified:
                    LOG.info("公网 HTTPS 已回到本进程：Cloudflare → 面板端口正常。Telegram 协议仍需客户端实测。")
                elif not reachable:
                    LOG.warning("尚未验证公网 HTTPS 回源：检查橙云、回源端口、SSL 模式、证书和 Cloudflare 挑战/缓存设置")
                verified = reachable
                next_probe = time.monotonic() + (300 if reachable else 60)
    finally:
        for child in reversed(children):
            stop_process(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "config.json"))
    parser.add_argument("--check-config", action="store_true", help="只检查配置，不下载、不启动服务")
    args = parser.parse_args()
    try:
        c = load_config(Path(args.config).resolve())
        if args.check_config:
            print(f"配置格式有效：域名 {c['domain']}；监听端口 {c['listen_port']}。未测试网络。")
            return 0
        init_logging()
        if os.name == "posix":
            import fcntl
            lockfile = (RUNTIME / "launcher.lock").open("a")
            try:
                fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise SetupError("已有一个 main.py 在运行，请先停止旧进程") from exc
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: STOP.set())
        secret = ensure_secret(c)
        LOG.info("读取配置完成；正在准备无交互运行环境")
        components = prepare_components(c)
        failures = 0
        while not STOP.is_set():
            try:
                supervise(c, components, secret)
                return 0
            except SetupError as exc:
                failures += 1
                LOG.error(redact(str(exc)))
                if failures >= 5:
                    raise SetupError("连续 5 次服务异常，停止自动重试；请修正上方问题后在面板重启") from exc
                LOG.info("%s 秒后重试（%s/5）", min(5 * failures, 30), failures)
                STOP.wait(min(5 * failures, 30))
        return 0
    except KeyboardInterrupt:
        return 0
    except (SetupError, OSError, ValueError) as exc:
        message = redact(str(exc))
        if LOG.handlers:
            LOG.error(message)
        else:
            print("启动失败：" + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
