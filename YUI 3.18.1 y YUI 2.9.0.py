#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de Auditoría para Detectar Librerías Obsoletas y Vulnerabilidades
ADVERTENCIA: Usar solo en sistemas autorizados para pruebas de penetración

Este script detecta librerías obsoletas como YUI y verifica vulnerabilidades conocidas.
"""

import requests
import json
import re
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Deshabilitar advertencias SSL para conexiones inseguras (solo para pruebas)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ObsoleteLibraryScanner:
    def __init__(self, target_url, output_dir="library_audit"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.session = requests.Session()
        self.session.verify = False  # Deshabilitar verificación SSL para pruebas
        self.obsolete_libraries = {}
        self.vulnerabilities = {}
        
        # Crear directorio de salida
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        
        print(f"[+] Iniciando auditoría de librerías obsoletas en: {self.target_url}")
        print(f"[+] Directorio de salida: {self.output_dir}")
    
    def scan_for_libraries(self):
        """Escanea el sitio en busca de librerías obsoletas"""
        print("\n[+] Iniciando escaneo de librerías obsoletas...")
        
        # URLs comunes para analizar
        urls_to_check = [
            self.target_url,
            f"{self.target_url}/login",
            f"{self.target_url}/index.php",
            f"{self.target_url}/home",
        ]
        
        # Agregar URLs encontradas en el sitemap si existe
        sitemap_urls = self.get_sitemap_urls()
        urls_to_check.extend(sitemap_urls[:10])  # Limitar a 10 URLs del sitemap
        
        # Escanear en paralelo
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.analyze_page, url): url for url in urls_to_check}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    libraries = future.result()
                    if libraries:
                        self.obsolete_libraries[url] = libraries
                        print(f"[✓] Analizado: {url} - Librerías encontradas: {len(libraries)}")
                except Exception as e:
                    print(f"[!] Error analizando {url}: {str(e)}")
        
        # Mostrar resultados
        self.display_results()
    
    def analyze_page(self, url):
        """Analiza una página en busca de librerías obsoletas"""
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return self.extract_libraries_from_content(response.text, url)
            return []
        except Exception as e:
            print(f"[!] Error al acceder a {url}: {str(e)}")
            return []
    
    def extract_libraries_from_content(self, html_content, page_url):
        """Extrae librerías del contenido HTML"""
        libraries = []
        
        # Buscar en etiquetas <script> y <link>
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Buscar scripts externos
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src')
            if src:
                library = self.identify_library(src, html_content)
                if library:
                    libraries.append(library)
        
        # Buscar enlaces CSS
        links = soup.find_all('link', href=True)
        for link in links:
            href = link.get('href')
            if href and ('.css' in href or 'stylesheet' in str(link)):
                library = self.identify_library(href, html_content)
                if library:
                    libraries.append(library)
        
        # Buscar en comentarios y código JavaScript
        libraries.extend(self.find_libraries_in_js_code(html_content))
        
        return libraries
    
    def identify_library(self, url_path, content=""):
        """Identifica si una URL corresponde a una librería obsoleta"""
        url_path_lower = url_path.lower()
        
        # Base de datos de librerías obsoletas conocidas
        obsolete_libs = {
            # YUI - Yahoo User Interface Library (DESCONTINUADA)
            'yui': {
                'patterns': [
                    r'yui[\/\$$([^\/\$$+)[\/\$$build',
                    r'yui-([^\/\$$+)[\/\$$build',
                    r'yahoo-dom-event',
                    r'yuiloader',
                    r'yui-skin'
                ],
                'versions': ['2.9.0', '3.18.1', '2.8.2', '3.3.0'],
                'risk': 'ALTO',
                'description': 'Yahoo User Interface Library descontinuada desde 2014',
                'cves': ['CVE-2012-5881', 'CVE-2012-5882', 'CVE-2013-0305'],
                'recommendation': 'Reemplazar con librerías modernas como jQuery, React, Vue.js'
            },
            
            # jQuery UI (versiones antiguas)
            'jquery-ui': {
                'patterns': [r'jquery-ui[-\.]([0-9]+\.[0-9]+\.[0-9]+)'],
                'versions': ['1.8.24', '1.9.2', '1.10.4'],
                'risk': 'MEDIO',
                'description': 'Versiones antiguas con vulnerabilidades XSS y CSRF',
                'cves': ['CVE-2010-0439', 'CVE-2016-7106'],
                'recommendation': 'Actualizar a la última versión estable'
            },
            
            # Prototype.js
            'prototype': {
                'patterns': [r'prototype[-\.]([0-9]+\.[0-9]+\.[0-9]+)'],
                'versions': ['1.6.1', '1.7.0', '1.7.1'],
                'risk': 'ALTO',
                'description': 'Framework JavaScript descontinuado con múltiples vulnerabilidades',
                'cves': ['CVE-2013-2884', 'CVE-2013-2885'],
                'recommendation': 'Migrar a frameworks modernos'
            },
            
            # Dojo Toolkit (versiones antiguas)
            'dojo': {
                'patterns': [r'dojo[-\.]([0-9]+\.[0-9]+\.[0-9]+)'],
                'versions': ['1.4.3', '1.5.0', '1.6.1'],
                'risk': 'MEDIO',
                'description': 'Versiones antiguas con vulnerabilidades de seguridad',
                'cves': ['CVE-2015-5117', 'CVE-2015-5118'],
                'recommendation': 'Actualizar o reemplazar'
            },
            
            # SWFObject (Flash)
            'swfobject': {
                'patterns': [r'swfobject[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)'],
                'versions': ['2.2', '2.1', '1.5'],
                'risk': 'ALTO',
                'description': 'Librería Flash descontinuada (Adobe Flash EOL)',
                'cves': ['CVE-2015-0311', 'CVE-2015-0313'],
                'recommendation': 'Eliminar uso de Flash'
            }
        }
        
        # Verificar cada librería obsoleta
        for lib_name, lib_info in obsolete_libs.items():
            # Verificar patrones en la URL
            for pattern in lib_info['patterns']:
                match = re.search(pattern, url_path_lower)
                if match:
                    version = match.group(1) if len(match.groups()) > 0 else "desconocida"
                    return {
                        'name': lib_name,
                        'version': version,
                        'url': url_path,
                        'risk': lib_info['risk'],
                        'description': lib_info['description'],
                        'cves': lib_info['cves'],
                        'recommendation': lib_info['recommendation'],
                        'source': 'URL Pattern'
                    }
        
        # Verificar en el contenido si no se encontró en la URL
        if content:
            for lib_name, lib_info in obsolete_libs.items():
                # Buscar en el contenido de la página
                lib_patterns = [
                    rf'{lib_name}.*?version.*?[\'"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                    rf