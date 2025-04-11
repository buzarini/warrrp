#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import base64
import logging
import tracemalloc
from datetime import datetime
from zoneinfo import ZoneInfo
import subprocess
import ipaddress
from pathlib import Path
from typing import Generator, List, Optional, Dict
from multiprocessing import Pool, cpu_count
import hashlib

# Конфигурация
class Config:
    WARP_CIDR = [
        '162.159.192.0/24',
        '162.159.193.0/24',
        '162.159.195.0/24',
        '162.159.204.0/24',
        '188.114.96.0/24',
        '188.114.97.0/24',
        '188.114.98.0/24',
        '188.114.99.0/24'
    ]
    MAX_WORKERS = max(1, cpu_count() - 1)
    WARP_BIN_HASH = "a1b2c3d4e5f6..."  # SHA-256 оригинального бинарника

# Инициализация мониторинга памяти
tracemalloc.start()

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('warrrp.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def validate_binary(file_path: Path) -> bool:
    """Проверяет хеш бинарного файла."""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash == Config.WARP_BIN_HASH
    except Exception as e:
        logger.error(f"Ошибка проверки бинарника: {e}")
        return False

def process_single_cidr(cidr: str) -> Generator[str, None, None]:
    """Обрабатывает один CIDR блок."""
    for host in ipaddress.IPv4Network(cidr).hosts():
        yield str(host)

def generate_ips_parallel() -> Generator[str, None, None]:
    """Параллельная генерация IP-адресов."""
    with Pool(Config.MAX_WORKERS) as pool:
        for ip_chunk in pool.imap_unordered(process_single_cidr, Config.WARP_CIDR):
            yield from ip_chunk

def create_ip_file() -> bool:
    """Создает файл IP с прогресс-баром."""
    try:
        total_ips = sum(ipaddress.IPv4Network(cidr).num_addresses - 2 for cidr in Config.WARP_CIDR)
        progress = 0
        
        with open(IP_TXT_PATH, 'w', encoding='utf-8') as f:
            for ip in generate_ips_parallel():
                f.write(f"{ip}\n")
                progress += 1
                if progress % 10_000 == 0:
                    mem_usage = tracemalloc.get_traced_memory()
                    logger.info(
                        f"Прогресс: {progress}/{total_ips} | "
                        f"Память: {mem_usage[0]/1024/1024:.2f}MB"
                    )
        
        return True
    except Exception as e:
        logger.error(f"Ошибка создания файла IP: {e}", exc_info=True)
        return False

def run_warp_with_retry(max_retries: int = 3) -> bool:
    """Запускает Warp с повторами при ошибках."""
    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                [WARP_SERVER_SCANNER_PATH],
                capture_output=True,
                text=True,
                check=True,
                timeout=300
            )
            logger.debug(f"Warp output (attempt {attempt+1}):\n{result.stdout[:500]}")
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Таймаут Warp (попытка {attempt+1})")
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка Warp (попытка {attempt+1}): {e.stderr}")
    
    return False

def analyze_results() -> Optional[Dict[str, float]]:
    """Анализирует результаты с метриками."""
    servers = []
    try:
        with open(SERVER_SCAN_RESULTS_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                servers.append({
                    'ip': row['ip'],
                    'latency': float(row['latency']),
                    'jitter': float(row['jitter'])
                })
                if len(servers) >= 2:
                    break
        
        if len(servers) < 2:
            return None
            
        return {
            'primary': servers[0]['ip'],
            'backup': servers[1]['ip'],
            'avg_latency': (servers[0]['latency'] + servers[1]['latency']) / 2
        }
    except Exception as e:
        logger.error(f"Ошибка анализа: {e}", exc_info=True)
        return None

def generate_config(config_data: Dict) -> bool:
    """Генерирует конфиг с расширенными параметрами."""
    try:
        config_content = f"""# Warp Configuration
primary = warp://{config_data['primary']}?ifp=50-100&ifps=50-100&ifpd=3-6
backup = warp://{config_data['backup']}
avg_latency = {config_data['avg_latency']:.2f}ms
updated = {datetime.now(ZoneInfo("Europe/Moscow")).strftime("%Y-%m-%d %H:%M %Z")}
"""
        with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(base64.b64encode(config_content.encode()).decode())
        
        return True
    except Exception as e:
        logger.error(f"Ошибка генерации конфига: {e}", exc_info=True)
        return False

def main():
    """Улучшенная основная функция."""
    logger.info("=== Запуск WARRRP Scanner v2 ===")
    
    # Проверка бинарника
    if not validate_binary(WARP_SERVER_SCANNER_PATH):
        logger.critical("Неверная контрольная сумма бинарника!")
        return

    # Генерация IP
    if not create_ip_file():
        return

    # Сканирование
    if not run_warp_with_retry():
        return

    # Анализ результатов
    scan_data = analyze_results()
    if not scan_data:
        return

    # Генерация конфига
    if not generate_config(scan_data):
        return

    logger.info("=== Успешно завершено ===")
    logger.info(f"Использовано памяти: {tracemalloc.get_traced_memory()[1]/1024/1024:.2f}MB")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Прервано пользователем")
    except Exception as e:
        logger.critical(f"Критическая ошибка: {e}", exc_info=True)
    finally:
        tracemalloc.stop()
