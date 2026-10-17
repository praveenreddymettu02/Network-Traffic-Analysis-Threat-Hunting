"""TShark/Wireshark detection utility for Windows.

Searches common installation paths and validates the executable.
Does NOT hardcode a single path — checks multiple locations.
"""

import os
import subprocess
from utils.logger import setup_logger

logger = setup_logger('tshark_detector')

# Common Windows installation paths (checked in order)
_COMMON_PATHS = [
    r'C:\Program Files\Wireshark\tshark.exe',
    r'C:\Program Files (x86)\Wireshark\tshark.exe',
    r'D:\Program Files\Wireshark\tshark.exe',
    r'D:\Wireshark\tshark.exe',
]


def find_tshark():
    """Detect tshark.exe on the system.

    Returns:
        str or None: Absolute path to tshark.exe, or None if not found.
    """
    # 1. Check environment variable / config
    from config import Config
    if Config.TSHARK_PATH and os.path.isfile(Config.TSHARK_PATH):
        logger.info("TShark found from config: %s", Config.TSHARK_PATH)
        return Config.TSHARK_PATH

    # 2. Check if tshark is on PATH
    try:
        result = subprocess.run(
            ['tshark', '--version'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            logger.info("TShark found on PATH")
            return 'tshark'
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 3. Search common installation paths
    for path in _COMMON_PATHS:
        if os.path.isfile(path):
            logger.info("TShark found at: %s", path)
            return path

    # 4. Search Windows registry (Wireshark installer registers here)
    try:
        import winreg
        for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            try:
                key = winreg.OpenKey(
                    hive,
                    r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wireshark.exe'
                )
                install_dir = winreg.QueryValue(key, 'Path')
                winreg.CloseKey(key)
                if install_dir:
                    tshark_path = os.path.join(install_dir, 'tshark.exe')
                    if os.path.isfile(tshark_path):
                        logger.info("TShark found via registry: %s", tshark_path)
                        return tshark_path
            except (OSError, WindowsError):
                continue
    except ImportError:
        pass  # Not on Windows

    logger.warning("TShark not found on this system")
    return None


def validate_tshark(path):
    """Validate that a tshark executable works.

    Args:
        path: Path to tshark executable.

    Returns:
        dict: {'valid': bool, 'version': str or None, 'path': str}
    """
    if not path:
        return {'valid': False, 'version': None, 'path': None}

    try:
        result = subprocess.run(
            [path, '--version'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0] if result.stdout else 'Unknown'
            return {
                'valid': True,
                'version': version_line.strip(),
                'path': path
            }
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        logger.error("TShark validation failed: %s", e)

    return {'valid': False, 'version': None, 'path': path}


def get_tshark_info():
    """Get TShark information (detect + validate).

    Returns:
        dict: {'available': bool, 'path': str or None, 'version': str or None}
    """
    path = find_tshark()
    if not path:
        return {'available': False, 'path': None, 'version': None}

    info = validate_tshark(path)
    return {
        'available': info['valid'],
        'path': path,
        'version': info.get('version')
    }
