import re
import os
import time
import urllib.parse
import base64
import json
import sys
import shutil
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import parse_qs, unquote

HAS_MSVCRT = False
if os.name == 'nt':
    try:
        import msvcrt
        HAS_MSVCRT = True
    except ImportError:
        pass

LINK_PATTERNS = [
    re.compile(r'(vmess://[^\s"]+)', re.IGNORECASE),
    re.compile(r'(vless://[^\s"]+)', re.IGNORECASE),
    re.compile(r'(trojan://[^\s"]+)', re.IGNORECASE),
    re.compile(r'(ss://[^\s"]+)', re.IGNORECASE),
    re.compile(r'(hysteria2://[^\s"]+)', re.IGNORECASE),
    re.compile(r'(hy2://[^\s"]+)', re.IGNORECASE),
    re.compile(r'(tuic://[^\s"]+)', re.IGNORECASE)
]

SNI_PARAMS = ['sni=', 'host=', 'servername=', 'peer=']
SNI_REGEXES = {p: re.compile(f"[?&]{p}([^&?#]+)", re.IGNORECASE) for p in SNI_PARAMS}
REALITY_HOST_REGEX = re.compile(r'[?&]host=([^&?#]+)', re.IGNORECASE)

def normalize_uuid(u):    return u.strip().lower().replace('{','').replace('}','') if u else ""
def normalize_server(s):  return s[1:-1] if s and s.startswith('[') and s.endswith(']') else (s.strip() if s else "")
def normalize_port(p):    return str(p).strip() if p else "443"
def normalize_param(v):   return v.strip().lower() if v else ""

def extract_individual_links(line: str) -> list[str]:
    links = []
    for pattern in LINK_PATTERNS:
        found = pattern.findall(line)
        links.extend(found)
    return links if links else [line.strip()] if line.strip() else []

def get_sni_from_link(link: str):
    for param, regex in SNI_REGEXES.items():
        match = regex.search(link)
        if match:
            value = match.group(1)
            try:
                value = urllib.parse.unquote(value)
            except:
                pass
            value = value.split('#')[0].split('&')[0].strip('"\' ')
            if value and not value.isspace():
                return value.strip(), param[:-1]
    if 'security=reality' in link.lower():
        match = REALITY_HOST_REGEX.search(link)
        if match:
            value = match.group(1)
            try:
                value = urllib.parse.unquote(value)
            except:
                pass
            value = value.split('#')[0].split('&')[0].strip('"\' ')
            if value and not value.isspace():
                return value.strip(), 'reality_host'
    if link.startswith('ss://'):
        sni_match = re.search(r'[?&]sni=([^&?#]+)', link, re.IGNORECASE)
        if sni_match:
            value = sni_match.group(1)
            try:
                value = urllib.parse.unquote(value)
            except:
                pass
            return value.strip(), 'sni'
        try:
            at_part = link.split('@', 1)[-1].split('?', 1)[0].split('#', 1)[0]
            server = at_part.split(':', 1)[0]
            if server and '.' in server:
                return server.strip(), 'server'
        except:
            pass
    return None, 'none'

def parse_vless(link):
    if not link.startswith('vless://'): return None
    try:
        link = link[8:]
        name = unquote(link.split('#', 1)[1]) if '#' in link else ""
        main = link.split('#')[0]
        addr_part, param_part = main.split('?', 1) if '?' in main else (main, "")
        uuid, server_part = main.split('@', 1) if '@' in addr_part else ("", addr_part)
        uuid = normalize_uuid(uuid)

        server, port = "", "443"
        if ':' in server_part:
            if server_part.startswith('['):
                i = server_part.index(']')
                server = server_part[1:i]
                pstr = server_part[i+1:]
                if pstr.startswith(':'): port = pstr[1:]
            else:
                parts = server_part.split(':')
                server = parts[0]
                if len(parts) > 1: port = parts[1]

        server = normalize_server(server)
        port = normalize_port(port)

        params = parse_qs(param_part)
        security   = normalize_param(params.get('security',   [''])[0])
        type_      = normalize_param(params.get('type',       [''])[0])
        host       = normalize_param(params.get('host',       [''])[0])
        path       = normalize_param(params.get('path',       [''])[0])
        sni        = normalize_param(params.get('sni',        [''])[0])
        flow       = normalize_param(params.get('flow',       [''])[0])
        pbk        = normalize_param(params.get('pbk',        [''])[0])
        sid        = normalize_param(params.get('sid',        [''])[0])

        key_parts = [server, port, security, flow]
        if security == 'reality':
            rparts = [pbk, sid, sni]
            key_parts.append('|'.join(p for p in rparts if p))

        key = ':'.join(key_parts)

        return {
            'type': 'vless', 'protocol': 'vless', 'server': server, 'port': port,
            'uuid': uuid, 'security': security, 'type_param': type_, 'host': host,
            'path': path, 'sni': sni, 'flow': flow, 'pbk': pbk, 'sid': sid,
            'name': name, 'key': key, 'original': link
        }
    except:
        return None

def parse_vmess(link):
    if not link.startswith('vmess://'): return None
    try:
        encoded = link[8:]
        padding = 4 - len(encoded) % 4
        if padding != 4: encoded += '=' * padding
        config = json.loads(base64.b64decode(encoded).decode('utf-8'))

        server = normalize_server(config.get('add', ''))
        port   = normalize_port(config.get('port', '443'))
        uuid   = normalize_uuid(config.get('id', ''))
        sec    = normalize_param(config.get('security', ''))
        typ    = normalize_param(config.get('type', ''))
        host   = normalize_param(config.get('host', ''))
        path   = normalize_param(config.get('path', ''))
        sni    = normalize_param(config.get('sni', ''))
        net    = normalize_param(config.get('net', ''))

        key_parts = [server, port, uuid, sec, net, typ]
        if host: key_parts.append(host)
        if path: key_parts.append(path)
        key = ':'.join(key_parts)

        return {
            'type': 'vmess', 'protocol': 'vmess', 'server': server, 'port': port,
            'uuid': uuid, 'security': sec, 'type_param': typ, 'host': host,
            'path': path, 'sni': sni, 'net': net, 'ps': config.get('ps', ''),
            'key': key, 'original': link
        }
    except:
        return None

def parse_trojan(link):
    if not link.startswith('trojan://'): return None
    try:
        link = link[9:]
        name = unquote(link.split('#', 1)[1]) if '#' in link else ""
        main = link.split('#')[0]
        addr_part, param_part = main.split('?', 1) if '?' in main else (main, "")
        password, server_part = addr_part.split('@', 1) if '@' in addr_part else ("", addr_part)

        server, port = "", "443"
        if ':' in server_part:
            if server_part.startswith('['):
                i = server_part.index(']')
                server = server_part[1:i]
                pstr = server_part[i+1:]
                if pstr.startswith(':'): port = pstr[1:]
            else:
                parts = server_part.split(':')
                server = parts[0]
                if len(parts) > 1: port = parts[1]

        server = normalize_server(server)
        port = normalize_port(port)

        params = parse_qs(param_part)
        security = normalize_param(params.get('security', [''])[0])
        typ      = normalize_param(params.get('type',     [''])[0])
        host     = normalize_param(params.get('host',     [''])[0])
        path     = normalize_param(params.get('path',     [''])[0])
        sni      = normalize_param(params.get('sni',      [''])[0])

        key_parts = [server, port, password, security, typ]
        if host: key_parts.append(host)
        if path: key_parts.append(path)
        if sni:  key_parts.append(sni)
        key = ':'.join(key_parts)

        return {
            'type': 'trojan', 'protocol': 'trojan', 'server': server, 'port': port,
            'password': password, 'security': security, 'type_param': typ,
            'host': host, 'path': path, 'sni': sni, 'name': name, 'key': key,
            'original': link
        }
    except:
        return None

def parse_ss(link):
    if not link.startswith('ss://'): return None
    try:
        content = link[5:]
        if '#' in content:
            content, name = content.split('#', 1)
            name = unquote(name)
        else:
            name = ""
        if '?' in content:
            content, params_str = content.split('?', 1)
            params = parse_qs(params_str)
            sni = normalize_param(params.get('sni', [''])[0])
        else:
            sni = ""
        if re.match(r'^[A-Za-z0-9+/=]+$', content):
            try:
                decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8', errors='ignore')
                if '@' in decoded:
                    method_pass, server_port = decoded.split('@', 1)
                    method, password = method_pass.split(':', 1) if ':' in method_pass else (method_pass, '')
                    server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
                else:
                    return None
            except:
                return None
        else:
            if '@' in content:
                method_pass, server_port = content.split('@', 1)
                method, password = method_pass.split(':', 1) if ':' in method_pass else (method_pass, '')
                server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
            else:
                return None

        server = normalize_server(server)
        port = normalize_port(port)
        key = f"ss:{server}:{port}:{method}:{password}"
        return {
            'type': 'ss', 'protocol': 'ss', 'server': server, 'port': port,
            'method': method, 'password': password, 'sni': sni, 'name': name,
            'key': key, 'original': link
        }
    except:
        return None

def parse_hysteria2(link):
    if not (link.startswith('hysteria2://') or link.startswith('hy2://') or link.startswith('hysteria://')):
        return None
    try:
        if link.startswith('hysteria://'):
            link = 'hysteria2://' + link[10:]
        if link.startswith('hy2://'):
            link = 'hysteria2://' + link[5:]
        content = link[12:]
        if '#' in content:
            content, name = content.split('#', 1)
            name = unquote(name)
        else:
            name = ""
        if '?' in content:
            base, param_str = content.split('?', 1)
            params = parse_qs(param_str)
            sni = normalize_param(params.get('sni', [''])[0])
        else:
            base = content
            sni = ""
        if '@' in base:
            auth, server_port = base.split('@', 1)
        else:
            auth, server_port = "", base
        server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
        server = normalize_server(server)
        port = normalize_port(port)
        key = f"hysteria2:{server}:{port}:{sni}" if sni else f"hysteria2:{server}:{port}"
        return {
            'type': 'hysteria2', 'protocol': 'hysteria2', 'server': server, 'port': port,
            'sni': sni, 'name': name, 'key': key, 'original': link
        }
    except:
        return None

def parse_tuic(link):
    if not link.startswith('tuic://'): return None
    try:
        content = link[7:]
        if '#' in content:
            content, name = content.split('#', 1)
            name = unquote(name)
        else:
            name = ""
        if '?' in content:
            base, param_str = content.split('?', 1)
            params = parse_qs(param_str)
        else:
            base = content
            params = {}
        if '@' not in base:
            return None
        auth_host = base.split('@')
        auth = auth_host[0]
        host_port = auth_host[1]
        if ':' in auth:
            uuid, password = auth.split(':', 1)
        else:
            uuid, password = auth, ""
        if ':' in host_port:
            host, port = host_port.split(':', 1)
        else:
            host, port = host_port, "443"
        uuid = normalize_uuid(uuid)
        server = normalize_server(host)
        port = normalize_port(port)
        sni = normalize_param(params.get('sni', [''])[0])
        security = normalize_param(params.get('security', [''])[0])
        alpn = normalize_param(params.get('alpn', [''])[0])
        key_parts = [server, port, uuid, password, security, alpn]
        if sni:
            key_parts.append(sni)
        key = ':'.join(key_parts)
        return {
            'type': 'tuic', 'protocol': 'tuic', 'server': server, 'port': port,
            'uuid': uuid, 'password': password, 'sni': sni, 'security': security,
            'alpn': alpn, 'name': name, 'key': key, 'original': link
        }
    except:
        return None

def parse_link(link: str):
    link = link.strip()
    if link.startswith('vless://'):     return parse_vless(link)
    if link.startswith('vmess://'):     return parse_vmess(link)
    if link.startswith('trojan://'):    return parse_trojan(link)
    if link.startswith('ss://'):        return parse_ss(link)
    if link.startswith('hysteria2://') or link.startswith('hy2://') or link.startswith('hysteria://'):
        return parse_hysteria2(link)
    if link.startswith('tuic://'):      return parse_tuic(link)
    return None

def test_contains_whitelist(sni, whitelist):
    if not sni:
        return None
    sni_lower = sni.lower()
    for wl in whitelist:
        wl_lower = wl.lower()
        if not wl_lower:
            continue
        if sni_lower == wl_lower or sni_lower.endswith(f".{wl_lower}"):
            return wl
        if wl_lower in sni_lower:
            idx = sni_lower.find(wl_lower)
            if idx == 0 or sni_lower[idx-1] == '.':
                after = idx + len(wl_lower)
                if after == len(sni_lower) or sni_lower[after] in ('.', ':'):
                    return wl
    return None

def backup_file_if_exists(src_path: str, backups_dir: str):
    if os.path.exists(src_path):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = os.path.basename(src_path)
        dst = os.path.join(backups_dir, f"{os.path.splitext(name)[0]}_backup_{ts}{os.path.splitext(name)[1]}")
        shutil.copy2(src_path, dst)

def wait_for_esc():
    if HAS_MSVCRT:
        print("\n\033[93mНажмите ESC для выхода...\033[0m")
        while True:
            if msvcrt.getch() == b'\x1b':
                break
    else:
        print("\n\033[93mНажмите Enter для выхода...\033[0m")
        input()

def colored_print(text, color='White'):
    colors = {
        'Green': '\033[92m', 'Red': '\033[91m', 'Yellow': '\033[93m',
        'Cyan': '\033[96m', 'Blue': '\033[94m', 'Magenta': '\033[95m',
        'Gray': '\033[90m', 'White': '\033[97m',
    }
    print(f"{colors.get(color, '')}{text}\033[0m", flush=True)

def estimate_processing_time(total_links):
    est = 0.1 + 0.005 * total_links
    est = max(est, 0.2)
    if est < 60:
        return f"~{round(est, 1)} сек"
    m, s = divmod(round(est), 60)
    return f"~{m} мин {s} сек"

def show_sni_statistics(proc_time, good_count, total, good_stats, bad_stats, no_sni, sni_sources, sub_info):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\033[96mГотово за {proc_time:.1f} сек\033[0m\n")
    print(f"\033[92mПрошло whitelist: {good_count}\033[0m")
    print(f"\033[91mОтклонено: {total - good_count}\033[0m")
    perc = round(good_count / total * 100, 2) if total else 0
    print(f"\033[97mПроцент совпадений: {perc}%\033[0m\n")

    if sub_info:
        print("\033[96mПо файлам:\033[0m")
        for fn, allc, goodc in sub_info:
            p = round(goodc / allc * 100, 2) if allc else 0
            print(f"  \033[90m{fn.ljust(45)}: {allc} → {goodc} ({p}%)\033[0m")
        print()

    if no_sni:
        print(f"\033[93mБез SNI: {no_sni}\033[0m\n")

    if sni_sources:
        print("\033[96mИсточники SNI:\033[0m")
        for src, cnt in sorted(sni_sources.items(), key=lambda x: x[1], reverse=True):
            print(f"  \033[90m{src.ljust(15)}: {cnt}\033[0m")
        print()

    if good_stats:
        print("\033[96mТоп в whitelist:\033[0m")
        for d, c in sorted(good_stats.items(), key=lambda x: x[1], reverse=True)[:12]:
            print(f"  \033[92m{d.ljust(45)} {c}\033[0m")

    if bad_stats:
        print("\n\033[96mТоп отклонённых:\033[0m")
        for d, c in sorted(bad_stats.items(), key=lambda x: x[1], reverse=True)[:12]:
            print(f"  \033[91m{d.ljust(45)} {c}\033[0m")
        print()

    print("\033[92msubWhitelist.txt  → промежуточный результат\033[0m")
    print("\033[91msubNo.txt         → не подошли по SNI\033[0m\n")
    print("\033[90mgithub.com/xLyouLx\033[0m")

def filter_duplicates():
    input_file = "subWhitelist.txt"
    if not os.path.exists(input_file):
        print("\033[91msubWhitelist.txt не найден — дедупликацию пропускаем\033[0m")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        links = [l.strip() for l in f if l.strip()]

    if not links:
        print("\033[93msubWhitelist.txt пустой\033[0m")
        return

    total = len(links)
    print(f"\n\033[96mЗапускаю проверку дубликатов...\033[0m")
    print(f"Всего ссылок: {total}")
    print(f"Примерное время: {estimate_processing_time(total)}\n")

    start = time.time()
    seen = set()
    unique = []
    dups = []
    protocols = defaultdict(int)

    for i, link in enumerate(links, 1):
        parsed = parse_link(link)
        if parsed and 'key' in parsed:
            prot = parsed['protocol']
            protocols[prot] += 1
            key = parsed['key']
            if key in seen:
                dups.append(link)
                print(f"{i}/{total} \033[91mDUP [{prot}] {key}\033[0m")
            else:
                seen.add(key)
                unique.append(link)
                print(f"{i}/{total} \033[92mUNIQUE [{prot}] {key}\033[0m")
        else:
            protocols['unknown'] += 1
            if link in seen:
                dups.append(link)
                print(f"{i}/{total} \033[91mDUP [unknown] {link[:80]}\033[0m")
            else:
                seen.add(link)
                unique.append(link)
                print(f"{i}/{total} \033[92mUNIQUE [unknown] {link[:80]}\033[0m")

    with open("NoDuble.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique) + '\n')
    with open("Duble.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(dups) + '\n')

    t = round(time.time() - start, 1)

    os.system('cls' if os.name == 'nt' else 'clear')
    colored_print(f"Дедупликация завершена за {t} сек", 'Cyan')
    colored_print(f"Уникальных   → {len(unique)} (NoDuble.txt)", 'Green')
    colored_print(f"Дубликатов   → {len(dups)} (Duble.txt)", 'Red')
    colored_print(f"Всего было   → {len(links)}\n", 'White')

    if protocols:
        colored_print("По протоколам:", 'Cyan')
        for p, c in sorted(protocols.items()):
            col = 'Gray' if p == 'unknown' else 'Green'
            colored_print(f"  {p.ljust(12)} : {c}", col)
        print()

    colored_print("github.com/xLyouLx", 'Gray')

def start_sni_filter():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sub_dir    = os.path.join(script_dir, "sub")
    backups    = os.path.join(script_dir, "backups")
    wl_file    = os.path.join(script_dir, "whitelist.txt")
    temp_wl    = os.path.join(script_dir, "subWhitelist.txt")
    temp_no    = os.path.join(script_dir, "subNo.txt")

    if not os.path.exists(wl_file):
        print("\033[91mwhitelist.txt не найден\033[0m")
        wait_for_esc()
        return

    if not os.path.exists(sub_dir):
        print("\033[91mПапка sub не найдена\033[0m")
        wait_for_esc()
        return

    os.makedirs(backups, exist_ok=True)
    backup_file_if_exists(temp_wl, backups)
    backup_file_if_exists(temp_no, backups)

    sub_files = []
    for root, _, files in os.walk(sub_dir):
        for f in files:
            if f.lower().endswith('.txt'):
                rel_path = os.path.relpath(os.path.join(root, f), sub_dir)
                sub_files.append(rel_path)

    if not sub_files:
        print("\033[93mВ папке sub (и подпапках) нет .txt файлов\033[0m")
        wait_for_esc()
        return

    with open(wl_file, 'r', encoding='utf-8') as f:
        whitelist = [l.strip() for l in f if l.strip()]
    if not whitelist:
        print("\033[91mwhitelist.txt пуст\033[0m")
        wait_for_esc()
        return

    open(temp_wl, 'w', encoding='utf-8').close()
    open(temp_no, 'w', encoding='utf-8').close()

    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[96mSNI Filter + Deduplication\033[0m")
    print(f"\033[90mФайлов: {len(sub_files)} | whitelist доменов: {len(whitelist)}\033[0m\n")

    link_sources = []
    file_counts = {}
    print("Чтение файлов...")
    for rel_fn in sub_files:
        full_path = os.path.join(sub_dir, rel_fn)
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
            cnt = 0
            for line in lines:
                extracted = extract_individual_links(line)
                for lnk in extracted:
                    link_sources.append((lnk, rel_fn))
                    cnt += 1
            file_counts[rel_fn] = cnt
            print(f"  \033[90m{rel_fn}: {cnt}\033[0m")
        except Exception as e:
            print(f"  \033[91m{rel_fn}: {e}\033[0m")

    total = len(link_sources)
    if total == 0:
        print("\033[91mНет валидных ссылок\033[0m")
        wait_for_esc()
        return

    print(f"\nВсего: {total}\nФильтрация по SNI...\n")

    start_t = time.time()
    good_stats = Counter()
    bad_stats = Counter()
    good_cnt = 0
    no_sni_cnt = 0
    sni_src = Counter()
    file_good_cnt = {f: 0 for f in sub_files}

    good_buffer = []
    bad_buffer = []
    last_flush = time.time()
    FLUSH_INTERVAL = 60

    def flush_buffers():
        nonlocal last_flush
        if good_buffer:
            with open(temp_wl, 'a', encoding='utf-8') as f:
                f.write('\n'.join(good_buffer) + '\n')
            good_buffer.clear()
        if bad_buffer:
            with open(temp_no, 'a', encoding='utf-8') as f:
                f.write('\n'.join(bad_buffer) + '\n')
            bad_buffer.clear()
        last_flush = time.time()

    for i, (link, src_file) in enumerate(link_sources, 1):
        sni, src_param = get_sni_from_link(link)
        sni_src[src_param] += 1

        matched = test_contains_whitelist(sni, whitelist)

        if matched:
            good_stats[matched] += 1
            good_cnt += 1
            file_good_cnt[src_file] += 1
            good_buffer.append(link)
            print(f"{i}/{total} \033[92m+ [{src_param}] {matched} → {sni}\033[0m")
        else:
            bad_buffer.append(link)
            if sni:
                bad_stats[sni] += 1
            else:
                no_sni_cnt += 1
            print(f"{i}/{total} \033[91m- [{src_param}] → {sni or 'no SNI'}\033[0m")

        if time.time() - last_flush >= FLUSH_INTERVAL:
            flush_buffers()

    flush_buffers()

    proc_time = time.time() - start_t
    sub_info = [(f, file_counts.get(f, 0), file_good_cnt.get(f, 0)) for f in sub_files]

    show_sni_statistics(proc_time, good_cnt, total, dict(good_stats), dict(bad_stats),
                        no_sni_cnt, dict(sni_src), sub_info)

    print("\n" + "═" * 60)
    ans = input("\033[96mЗапустить проверку на дубликаты? [Y/n] \033[0m").strip().lower()
    if ans in ('', 'y', 'да'):
        filter_duplicates()
    else:
        print("\033[93mДедупликация пропущена\033[0m")

    wait_for_esc()

if __name__ == "__main__":
    try:
        start_sni_filter()
    except KeyboardInterrupt:
        print("\n\033[91mПрервано пользователем\033[0m")
        wait_for_esc()
    except Exception as e:
        print(f"\n\033[91mОшибка: {e}\033[0m")
        wait_for_esc()
