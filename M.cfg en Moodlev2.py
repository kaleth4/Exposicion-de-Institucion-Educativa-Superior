import logging
import json
import re
from typing import Dict, Optional, Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# Configuración de logging profesional
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MoodleSecurityAuditor:
    """
    Auditor profesional para la detección de fugas de información en plataformas Moodle.
    Cumple con estándares de modularidad y manejo de excepciones.
    """

    def __init__(self, target_url: str, timeout: int = 10, proxy: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Auditor/1.0',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    def fetch_page(self, path: str) -> Optional[str]:
        """Obtiene el contenido de una página manejando errores de red."""
        try:
            url = urljoin(self.target_url, path)
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            return response.text
        except RequestException as e:
            logger.error(f"Error accediendo a {path}: {e}")
            return None

    def extract_m_cfg(self, html: str) -> Dict[str, Any]:
        """
        Extrae el objeto M.cfg usando una lógica de búsqueda por capas.
        """
        # Intento 1: Captura de objeto JSON directo en JS
        json_pattern = r'M\.cfg\s*=\s*(\{.*?\});'
        match = re.search(json_pattern, html, re.DOTALL)
        
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                logger.warning("Se detectó M.cfg pero el formato JSON es inválido.")

        # Intento 2: Búsqueda de pares clave-valor individuales (Fallback)
        keys_to_find = ['sesskey', 'wwwroot', 'userId', 'themerev']
        extracted = {}
        for key in keys_to_find:
            val_match = re.search(f'"{key}":"?([^",}]+)"?', html)
            if val_match:
                extracted[key] = val_match.group(1)
        
        return extracted

    def run_audit(self):
        """Ejecuta el flujo principal de auditoría."""
        logger.info(f"Iniciando auditoría en {self.target_url}")
        
        pages = ['/', '/login/index.php']
        results = {}

        for page in pages:
            content = self.fetch_page(page)
            if content:
                config = self.extract_m_cfg(content)
                if config:
                    results[page] = config
                    logger.info(f"Configuración sensible encontrada en {page}")

        self._generate_report(results)

    def _generate_report(self, data: Dict):
        """Genera una salida estructurada (podría ser a archivo JSON)."""
        if not data:
            logger.info("No se encontró información sensible.")
            return
        
        print("\n--- REPORTE DE AUDITORÍA ---")
        print(json.dumps(data, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    # Ejemplo de uso profesional
    TARGET = "https://cun.edu.co" 
    auditor = MoodleSecurityAuditor(TARGET)
    auditor.run_audit()
