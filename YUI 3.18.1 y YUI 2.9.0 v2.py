import logging
import re
import json
import requests
import urllib3
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Configuración de seguridad y silencio de advertencias
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class VulnerabilityDatabase:
    """Simula una base de datos externa de firmas de librerías."""
    DATA = {
        "yui": {
            "name": "Yahoo User Interface (YUI)",
            "risk": "CRITICAL",
            "deprecated_since": "2014",
            "cves": ["CVE-2012-5881", "CVE-2013-0305"]
        },
        "swfobject": {
            "name": "SWFObject (Flash)",
            "risk": "HIGH",
            "reason": "Flash Player EOL",
            "cves": ["CVE-2015-0311"]
        }
    }

class LibraryAuditor:
    def __init__(self, target_url: str, max_workers: int = 5):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers = {"User-Agent": "SecurityAuditor/2.0"}
        self.max_workers = max_workers
        self.results = []

    def get_assets(self, url: str) -> List[str]:
        """Extrae todos los archivos JS y CSS de una URL."""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Combinar src de scripts y href de links
            scripts = [s.get('src') for s in soup.find_all('script', src=True)]
            styles = [l.get('href') for l in soup.find_all('link', href=True)]
            
            return [requests.compat.urljoin(url, asset) for asset in scripts + styles]
        except Exception as e:
            logging.error(f"Error al analizar {url}: {e}")
            return []

    def identify_vulnerability(self, asset_url: str) -> Optional[Dict]:
        """Compara la URL del asset contra la base de datos de firmas."""
        asset_lower = asset_url.lower()
        
        for key, info in VulnerabilityDatabase.DATA.items():
            if key in asset_lower:
                # Intento de extraer versión mediante RegEx dinámico
                version_match = re.search(r'(\d+\.\d+\.\d+)', asset_url)
                version = version_match.group(1) if version_match else "Unknown"
                
                return {
                    "library": info["name"],
                    "version": version,
                    "url": asset_url,
                    "risk": info["risk"],
                    "cves": info.get("cves", [])
                }
        return None

    def run(self, paths: List[str]):
        """Ejecuta el escaneo en múltiples rutas de forma paralela."""
        urls = [f"{self.target_url}{p}" for p in paths]
        all_assets = set()

        logging.info(f"Escaneando {len(urls)} páginas en busca de librerías...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Paso 1: Recolectar assets de todas las páginas
            for assets in executor.map(self.get_assets, urls):
                all_assets.update(assets)

        logging.info(f"Se encontraron {len(all_assets)} recursos únicos. Analizando vulnerabilidades...")

        # Paso 2: Analizar cada asset encontrado
        for asset in all_assets:
            vulnerability = self.identify_vulnerability(asset)
            if vulnerability:
                self.results.append(vulnerability)
                logging.warning(f"¡VULNERABILIDAD DETECTADA!: {vulnerability['library']} en {asset}")

        self.export_report()

    def export_report(self):
        """Imprime un resumen profesional."""
        print("\n" + "="*60)
        print(f"{'REPORTE DE AUDITORÍA DE LIBRERÍAS':^60}")
        print("="*60)
        if not self.results:
            print("No se encontraron librerías obsoletas conocidas.")
        else:
            for res in self.results:
                print(f"[{res['risk']}] {res['library']} (v.{res['version']})")
                print(f"  > Origen: {res['url']}")
                print(f"  > CVEs: {', '.join(res['cves'])}\n")

if __name__ == "__main__":
    target = "https://cun.edu.co"
    auditor = LibraryAuditor(target)
    # Definimos rutas comunes de Moodle
    auditor.run(['/', '/login/index.php', '/lib/upgrade.txt'])
