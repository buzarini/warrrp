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

# Constants for paths
SCRIPT_DIR = Path(__file__).parent
WARP_SERVER_SCANNER_PATH = SCRIPT_DIR / 'bin' / 'warp'
SERVER_SCAN_RESULTS_PATH = SCRIPT_DIR / 'result.csv'
CONFIG_FILE_PATH = SCRIPT_DIR / 'config'
IP_TXT_PATH = SCRIPT_DIR / 'ip.txt'

# Cloudflare Warp CIDR ranges
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

def generate_ip_list() -> None:
    """Generate a list of all IP addresses from WARP_CIDR ranges and save to file."""
    if IP_TXT_PATH.exists():
        logger.info("ip.txt already exists, skipping generation.")
        return
    
    logger.info("Generating ip.txt file with all WARP IP addresses.")
    try:
        with IP_TXT_PATH.open('w') as file:
            for cidr in WARP_CIDR:
                network = ipaddress.IPv4Network(cidr)
                file.writelines(f"{host}\n" for host in network.hosts())
        logger.info("Successfully generated ip.txt file.")
    except Exception as e:
        logger.error(f"Failed to generate ip.txt: {e}")
        raise

def get_repository_name() -> str:
    """Returns the uppercase name of the repository."""
    return os.path.basename(os.path.dirname(SCRIPT_DIR)).upper()

def run_warp_server_scanner() -> None:
    """Runs the Warp server scanner binary."""
    if not WARP_SERVER_SCANNER_PATH.exists():
        raise RuntimeError(f"Warp binary not found at {WARP_SERVER_SCANNER_PATH}")

    try:
        WARP_SERVER_SCANNER_PATH.chmod(0o755)
        logger.info("Executing Warp server scanner...")
        result = subprocess.run(
            [WARP_SERVER_SCANNER_PATH], 
            check=True,
            capture_output=True,
            text=True
        )
        logger.debug(f"Warp scanner output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Warp execution failed with return code {e.returncode}")
        logger.error(f"Error output:\n{e.stderr}")
        raise RuntimeError("Warp execution failed") from e

def extract_top_two_servers() -> list[str]:
    """Extracts the top two server addresses from the CSV results."""
    try:
        with SERVER_SCAN_RESULTS_PATH.open() as csv_file:
            reader = csv.reader(csv_file)
            next(reader)  # Skip header
            return [row[0] for row in reader][:2]
    except FileNotFoundError:
        logger.error(f"CSV file not found at {SERVER_SCAN_RESULTS_PATH}")
        raise
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        raise

def get_last_update_time() -> str:
    """Returns the last update time of the result CSV file in Moscow time."""
    try:
        creation_time = SERVER_SCAN_RESULTS_PATH.stat().st_ctime
        moscow_tz = ZoneInfo("Europe/Moscow")
        local_time = datetime.fromtimestamp(creation_time, moscow_tz)
        return local_time.strftime("%Y-%m-%d %H:%M") + " Moscow Time"
    except OSError as e:
        logger.error(f"Error accessing the result CSV file: {e}")
        raise

def generate_warp_config(top_servers: list[str], last_update_time: str) -> None:
    """Generates and writes the Warp configuration based on the top servers."""
    if len(top_servers) < 2:
        raise ValueError("Need at least two servers to generate config")

    warp_config = (
        f"warp://{top_servers[0]}?ifp=50-100&ifps=50-100&ifpd=3-6&ifpm=m4#WARP&&detour=warp://{top_servers[1]}#DETOUR"
    )

    warp_hiddify_config = (
        f"#profile-title: base64:{base64.b64encode(get_repository_name().encode()).decode()}\n"
        f"#profile-update-interval: 1\n"
        f"#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n"
        f"#profile-web-page-url: https://github.com/buzarini/warrrp\n"
        f"#last-update: {last_update_time}\n"
        f"{warp_config}"
    )

    try:
        with CONFIG_FILE_PATH.open('wb') as config_file:
            config_file.write(base64.b64encode(warp_hiddify_config.encode()))
        logger.info("Successfully generated Warp configuration file.")
    except IOError as e:
        logger.error(f"Error writing to configuration file: {e}")
        raise

def clean_up() -> None:
    """Cleans up temporary files."""
    files_to_remove = [SERVER_SCAN_RESULTS_PATH, IP_TXT_PATH]
    for file in files_to_remove:
        try:
            file.unlink(missing_ok=True)
            logger.debug(f"Removed file: {file}")
        except OSError as e:
            logger.warning(f"Error removing file {file}: {e}")

def main() -> None:
    """Main function to run the warp server scanner and generate the config."""
    try:
        logger.info("Starting WARRRP script execution")
        
        # Generate IP list first
        generate_ip_list()
        
        # Run the scanner
        run_warp_server_scanner()
        
        # Process results
        top_servers = extract_top_two_servers()
        logger.info(f"Top servers found: {top_servers}")
        
        last_update_time = get_last_update_time()
        logger.info(f"Last update time: {last_update_time}")
        
        # Generate config
        generate_warp_config(top_servers, last_update_time)
        
        # Clean up
        clean_up()
        
        logger.info("WARRRP script completed successfully")
    except Exception as e:
        logger.critical(f"Script failed: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
