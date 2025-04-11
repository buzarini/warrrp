#!/usr/bin/env python3.13
import os
import csv
import base64
import logging
import ipaddress
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('warrrp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
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

class WarpConfigurator:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.warp_binary_path = self.script_dir / 'bin' / 'warp'
        self.ip_txt_path = self.script_dir / 'ip.txt'
        self.result_path = self.script_dir / 'result.csv'
        self.config_path = self.script_dir / 'config'
        self.best_ips_path = self.script_dir / 'best_ips.txt'
        
        # Moscow timezone
        self.tz = ZoneInfo("Europe/Moscow")

    def generate_ip_list(self) -> None:
        """Генерирует список IP-адресов на основе WARP_CIDR."""
        logger.info("Начало генерации списка IP-адресов")
        try:
            total_ips = sum(len(list(ipaddress.IPv4Network(cidr))) for cidr in WARP_CIDR)
            
            with self.ip_txt_path.open('w') as file:
                for cidr in WARP_CIDR:
                    for addr in ipaddress.IPv4Network(cidr):
                        file.write(f"{addr}\n")
            
            logger.info(f"Успешно сгенерирован файл с {total_ips} IP-адресами")
        except Exception as e:
            logger.error(f"Ошибка при генерации IP-адресов: {e}")
            raise

    def run_warp_scanner(self) -> None:
        """Запускает сканер WARP."""
        logger.info("Запуск сканера WARP")
        try:
            if not self.warp_binary_path.exists():
                raise FileNotFoundError(f"Бинарный файл WARP не найден: {self.warp_binary_path}")
            
            self.warp_binary_path.chmod(0o755)
            result = subprocess.run(
                [str(self.warp_binary_path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            if result.returncode != 0:
                logger.error(f"Ошибка выполнения WARP: {result.stderr}")
                raise RuntimeError("Сканер WARP завершился с ошибкой")
            
            logger.info("Сканирование WARP успешно завершено")
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка выполнения подпроцесса: {e}")
            raise
        except Exception as e:
            logger.error(f"Неожиданная ошибка при запуске WARP: {e}")
            raise

    def get_top_servers(self) -> list[str]:
        """Извлекает топ-2 сервера из результатов сканирования."""
        logger.info("Извлечение топ-2 серверов")
        try:
            with self.result_path.open('r') as csv_file:
                reader = csv.reader(csv_file)
                next(reader)  # Пропуск заголовка
                return [row[0] for row in reader][:2]
        except FileNotFoundError:
            logger.error(f"Файл результатов не найден: {self.result_path}")
            raise
        except Exception as e:
            logger.error(f"Ошибка чтения результатов: {e}")
            raise

    def get_last_update_time(self) -> str:
        """Возвращает время последнего обновления по московскому времени."""
        try:
            mtime = self.result_path.stat().st_mtime
            moscow_time = datetime.fromtimestamp(mtime, tz=self.tz)
            return moscow_time.strftime("%Y-%m-%d %H:%M") + " Москва, время"
        except Exception as e:
            logger.error(f"Ошибка получения времени обновления: {e}")
            return "Неизвестное время"

    def generate_config(self, top_servers: list[str], update_time: str) -> None:
        """Генерирует конфигурационный файл."""
        logger.info("Генерация конфигурации WARP")
        try:
            repo_name = os.path.basename(os.path.dirname(__file__)).upper()
            plus_key = os.getenv('PLUS_KEY', '')
            
            warp_config = (
                f"warp://{top_servers[0]}?ifp=50-100&ifps=50-100&ifpd=3-6&ifpm=m4#RU&&"
                f"detour=warp://{top_servers[1]}#DE"
            )
            
            config_content = (
                f"#profile-title: base64:{base64.b64encode(repo_name.encode()).decode()}\n"
                f"#profile-update-interval: 1\n"
                f"#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n"
                f"#profile-web-page-url: https://github.com/rzrhmrd/warrrp\n"
                f"#last-update: {update_time}\n"
                f"{warp_config}"
            )
            
            self.config_path.write_text(config_content)
            self.best_ips_path.write_text("\n".join(top_servers))
            
            logger.info("Конфигурационный файл успешно создан")
        except Exception as e:
            logger.error(f"Ошибка генерации конфигурации: {e}")
            raise

    def cleanup(self) -> None:
        """Очищает временные файлы."""
        logger.info("Очистка временных файлов")
        try:
            for file in [self.ip_txt_path, self.result_path, self.warp_binary_path]:
                if file.exists():
                    file.unlink()
                    logger.debug(f"Удален файл: {file}")
        except Exception as e:
            logger.error(f"Ошибка при очистке: {e}")
            raise

    def execute(self) -> None:
        """Основной метод выполнения скрипта."""
        try:
            logger.info("=== Начало работы скрипта WARRRP ===")
            
            # Генерация списка IP
            if not self.ip_txt_path.exists():
                self.generate_ip_list()
            else:
                logger.info("Файл IP уже существует, пропуск генерации")
            
            # Запуск сканера
            self.run_warp_scanner()
            
            # Получение результатов
            top_servers = self.get_top_servers()
            if len(top_servers) < 2:
                raise RuntimeError("Недостаточно серверов для конфигурации")
            
            # Генерация конфига
            update_time = self.get_last_update_time()
            self.generate_config(top_servers, update_time)
            
            # Очистка
            self.cleanup()
            
            logger.info("=== Скрипт успешно завершен ===")
        except Exception as e:
            logger.critical(f"Критическая ошибка: {e}")
            raise

if __name__ == "__main__":
    try:
        configurator = WarpConfigurator()
        configurator.execute()
    except Exception as e:
        logger.critical(f"Фатальная ошибка: {e}", exc_info=True)
        exit(1)
