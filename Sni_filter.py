import re
import os
import time
import urllib.parse
from collections import Counter
from datetime import datetime
import shutil
import sys

# Conditional import for msvcrt (Windows only)
HAS_MSVCRT = False
if os.name == 'nt':
    try:
        import msvcrt
        HAS_MSVCRT = True
    except ImportError:
        pass

def extract_individual_links(line: str) -> list[str]:
    """Extracts individual proxy links from a line, handles concatenated ones."""
    patterns = [
        r'(vmess://[^\s"]+)',
        r'(vless://[^\s"]+)',
        r'(trojan://[^\s"]+)'
    ]
    links = []
    for pattern in patterns:
        found = re.findall(pattern, line, re.IGNORECASE)
        links.extend(found)
    return links if links else [line.strip()] if line.strip() else []

def get_sni_from_link(link: str) -> tuple[str | None, str]:
    """Returns (sni_value, source_param)"""
    sni_params = ['sni=', 'host=', 'servername=', 'peer=']
    
    for param in sni_params:
        match = re.search(f"[?&]{param}([^&?#]+)", link, re.IGNORECASE)
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
        match = re.search(r'[?&]host=([^&?#]+)', link, re.IGNORECASE)
        if match:
            value = match.group(1)
            try:
                value = urllib.parse.unquote(value)
            except:
                pass
            value = value.split('#')[0].split('&')[0].strip('"\' ')
            if value and not value.isspace():
                return value.strip(), 'reality_host'
    
    return None, 'none'

def test_contains_whitelist(sni: str | None, whitelist: list[str]) -> str | None:
    """Returns matched whitelist domain or None"""
    if not sni:
        return None
    sni_lower = sni.lower()
    for wl in whitelist:
        wl_lower = wl.strip().lower()
        if not wl_lower:
            continue
        if sni_lower == wl_lower or sni_lower.endswith(f".{wl_lower}"):
            return wl.strip()
        if wl_lower in sni_lower:
            if re.search(f"(^|\\.){re.escape(wl_lower)}($|\\.|:)", sni_lower):
                return wl.strip()
    return None

def backup_file_if_exists(src_path: str, backups_dir: str):
    """Copies file to backups folder with timestamp if it exists"""
    if os.path.exists(src_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(src_path)
        backup_path = os.path.join(backups_dir, f"{os.path.splitext(filename)[0]}_backup_{timestamp}{os.path.splitext(filename)[1]}")
        shutil.copy2(src_path, backup_path)

def wait_for_esc():
    """Waits for key press to exit (ESC on Windows if available, else Enter)"""
    if HAS_MSVCRT:
        print("\n\033[93mНажмите ESC для выхода...\033[0m")
        while True:
            key = msvcrt.getch()
            if key == b'\x1b':  # ESC key
                break
    else:
        print("\n\033[93mНажмите Enter для выхода...\033[0m")
        input()

def show_statistics(processing_time: float, good_count: int, total_links: int, good_stats: dict, bad_stats: dict,
                    no_sni_count: int, sni_sources: dict, sub_files_info: list, unique_good: int):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"\033[96mГотово за {processing_time:.1f} сек\033[0m\n")
    print(f"\033[92mВ whitelist (до дедупа): {good_count}\033[0m")
    print(f"\033[92mВ whitelist (уникальных): {unique_good}\033[0m")
    print(f"\033[91mОтклонено: {total_links - good_count}\033[0m")
    percentage = round((good_count / total_links) * 100, 2) if total_links > 0 else 0
    print(f"\033[97mПроцент совпадений: {percentage}%\033[0m\n")
    
    if sub_files_info:
        print("\033[96mОбработанные файлы:\033[0m")
        for file_name, links_count, good_in_file in sub_files_info:
            file_percentage = round((good_in_file / links_count) * 100, 2) if links_count > 0 else 0
            print(f"  \033[90m{file_name.ljust(35)}: {links_count} ссылок, {good_in_file} подошло ({file_percentage}%)\033[0m")
        print()
    
    if no_sni_count > 0:
        print(f"\033[93mБез SNI/host вообще: {no_sni_count}\033[0m\n")
    
    if sni_sources:
        print("\033[96mОткуда брали SNI:\033[0m")
        for source, count in sorted(sni_sources.items(), key=lambda x: x[1], reverse=True):
            print(f"  \033[90m{source.ljust(15)}: {count}\033[0m")
        print()
    
    if good_stats:
        print("\033[96mТоп matched (в whitelist):\033[0m")
        for domain, count in sorted(good_stats.items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"  \033[92m{domain.ljust(45)} {count}\033[0m")
    
    if bad_stats:
        print("\n\033[96mТоп rejected SNI (не в whitelist):\033[0m")
        for domain, count in sorted(bad_stats.items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"  \033[91m{domain.ljust(45)} {count}\033[0m")
        print()
    
    print(f"\033[92msubWhitelist.txt → {unique_good} уникальных ссылок\033[0m")
    print(f"\033[91msubNo.txt        → {total_links - good_count} ссылок\033[0m\n")
    
    # Вот твоя серая подпись
    print("\033[90mgithub.com/xLyouLx\033[0m")

def start_sni_filter():
    script_path = os.path.dirname(os.path.abspath(__file__))
    sub_folder = os.path.join(script_path, "sub")
    backups_dir = os.path.join(script_path, "backups")
    whitelist_file = os.path.join(script_path, "whitelist.txt")
    output_whitelist = os.path.join(script_path, "subWhitelist.txt")
    output_no = os.path.join(script_path, "subNo.txt")
    
    if not os.path.exists(whitelist_file):
        print("\033[91mwhitelist.txt не найден\033[0m")
        wait_for_esc()
        return
    
    if not os.path.exists(sub_folder):
        print("\033[91mПапка sub не найдена\033[0m")
        wait_for_esc()
        return
    
    if not os.path.exists(backups_dir):
        os.makedirs(backups_dir)
    
    backup_file_if_exists(output_whitelist, backups_dir)
    backup_file_if_exists(output_no, backups_dir)
    
    sub_files = [f for f in os.listdir(sub_folder) if f.lower().endswith('.txt')]
    if not sub_files:
        print("\033[93mПапка 'sub' пуста или не содержит .txt файлов. Положите туда файлы с прокси-ссылками и запустите скрипт заново.\033[0m")
        wait_for_esc()
        return
    
    with open(whitelist_file, 'r', encoding='utf-8') as f:
        whitelist_domains = [line.strip() for line in f if line.strip()]
    if not whitelist_domains:
        print("\033[91mwhitelist.txt пустой\033[0m")
        wait_for_esc()
        return
    
    open(output_whitelist, 'w', encoding='utf-8').close()
    open(output_no, 'w', encoding='utf-8').close()
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[96mStrict SNI Filter 2025 — Final Edition\033[0m")
    print(f"\033[90mФайлов: {len(sub_files)} | Домены в whitelist: {len(whitelist_domains)}\033[0m\n")
    
    link_sources = []
    file_link_counts = {}
    
    print("Чтение файлов...")
    for sub_file in sub_files:
        file_path = os.path.join(sub_folder, sub_file)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
            count = 0
            for line in lines:
                for ilink in extract_individual_links(line):
                    link_sources.append((ilink, sub_file))
                    count += 1
            file_link_counts[sub_file] = count
            print(f"  \033[90m{sub_file}: {count} ссылок\033[0m")
        except Exception as e:
            print(f"  \033[91mОшибка {sub_file}: {e}\033[0m")
    
    total_links = len(link_sources)
    if total_links == 0:
        print("\033[91mСсылок нет — все файлы пустые или без валидных ссылок\033[0m")
        wait_for_esc()
        return
    
    print(f"\nВсего: {total_links}\nОбработка...\n")
    
    start_time = time.time()
    good_stats = Counter()
    bad_stats = Counter()
    good_count = 0
    no_sni_count = 0
    sni_sources = Counter()
    file_good_counts = {f: 0 for f in sub_files}
    seen_links = set()
    
    for idx, (link, source_file) in enumerate(link_sources, 1):
        sni, source_param = get_sni_from_link(link)
        sni_sources[source_param] += 1
        
        matched = test_contains_whitelist(sni, whitelist_domains)
        
        if matched:
            good_stats[matched] += 1
            good_count += 1
            file_good_counts[source_file] += 1
            
            if link not in seen_links:
                with open(output_whitelist, 'a', encoding='utf-8') as f:
                    f.write(link + '\n')
                seen_links.add(link)
            
            print(f"{idx}/{total_links} \033[92m+ [{source_param}] {matched} → {sni}\033[0m")
        else:
            with open(output_no, 'a', encoding='utf-8') as f:
                f.write(link + '\n')
            if sni:
                bad_stats[sni] += 1
            else:
                no_sni_count += 1
            print(f"{idx}/{total_links} \033[91m- [{source_param}] no match → {sni or 'no SNI'}\033[0m")
    
    processing_time = time.time() - start_time
    unique_good = len(seen_links)
    
    sub_files_info = [(f, file_link_counts.get(f, 0), file_good_counts.get(f, 0)) for f in sub_files]
    
    show_statistics(processing_time, good_count, total_links, dict(good_stats), dict(bad_stats),
                    no_sni_count, dict(sni_sources), sub_files_info, unique_good)
    
    wait_for_esc()

if __name__ == "__main__":
    try:
        start_sni_filter()
    except KeyboardInterrupt:
        print("\n\033[91mПрервано пользователем\033[0m")
        wait_for_esc()
    except Exception as e:
        print(f"\n\033[91mНеизвестная ошибка: {e}\033[0m")
        wait_for_esc()
