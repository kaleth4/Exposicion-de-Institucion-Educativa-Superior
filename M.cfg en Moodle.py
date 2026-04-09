#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de Auditoría para Extraer Información Sensible de Moodle
ADVERTENCIA: Usar solo en sistemas autorizados para pruebas de penetración

Este script detecta y extrae información sensible como el objeto M.cfg
que contiene metadatos críticos de sesión y usuario en Moodle.
"""

import requests
import json
import re
import urllib3
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

# Deshabilitar advertencias SSL para conexiones inseguras (solo para pruebas)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MoodleDisclosureScanner:
    def __init__(self, target_url, output_dir="moodle_audit"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.session = requests.Session()
        self.session.verify = False  # Deshabilitar verificación SSL para pruebas
        self.sensitive_data = {}
        
        # Crear directorio de salida
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        
        print(f"[+] Iniciando auditoría de Moodle en: {self.target_url}")
        print(f"[+] Directorio de salida: {self.output_dir}")
    
    def check_moodle_presence(self):
        """Verifica si el objetivo es una instalación de Moodle"""
        print("\n[+] Verificando presencia de Moodle...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code == 200:
                # Buscar indicadores de Moodle
                indicators = [
                    'Moodle',
                    'moodle',
                    'mdl_',
                    'course/view.php',
                    'login/index.php'
                ]
                
                content = response.text.lower()
                moodle_indicators = [ind for ind in indicators if ind.lower() in content]
                
                if moodle_indicators:
                    print(f"[✓] Instalación de Moodle detectada")
                    print(f"    Indicadores encontrados: {', '.join(moodle_indicators)}")
                    return True
                else:
                    print("[!] No se detectaron indicadores claros de Moodle")
                    # Preguntar si continuar igualmente
                    response = input("[?] ¿Continuar con el análisis? (y/N): ")
                    return response.lower() == 'y'
            else:
                print(f"[✗] Error al acceder al objetivo: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[✗] Error al verificar Moodle: {str(e)}")
            return False
    
    def extract_m_cfg(self):
        """Extrae el objeto M.cfg que contiene información sensible"""
        print("\n[+] Buscando objeto M.cfg en páginas de Moodle...")
        
        # URLs comunes donde puede aparecer M.cfg
        common_paths = [
            '/',                    # Página principal
            '/login/index.php',     # Página de login
            '/my/',                 # Página de inicio del usuario
            '/course/view.php',     # Vista de curso (necesita ID)
        ]
        
        m_cfg_found = False
        
        for path in common_paths:
            try:
                url = urljoin(self.target_url, path)
                print(f"[+] Analizando: {url}")
                
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Buscar el objeto M.cfg en el código fuente
                    m_cfg_data = self.parse_m_cfg_from_html(response.text)
                    if m_cfg_data:
                        print(f"[✓] M.cfg encontrado en {path}")
                        self.sensitive_data['m_cfg'] = m_cfg_data
                        self.save_m_cfg_data(m_cfg_data, path)
                        m_cfg_found = True
                        
                        # Mostrar información sensible encontrada
                        self.display_sensitive_info(m_cfg_data)
                        
                        # Verificar si hay más información sensible
                        self.extract_additional_sensitive_data(response.text)
                        
                time.sleep(1)  # Esperar para no sobrecargar el servidor
                
            except Exception as e:
                print(f"[!] Error analizando {path}: {str(e)}")
        
        if not m_cfg_found:
            print("[!] No se encontró M.cfg en las páginas analizadas")
            # Intentar búsqueda más exhaustiva
            self.exhaustive_m_cfg_search()
    
    def parse_m_cfg_from_html(self, html_content):
        """Extrae el objeto M.cfg del contenido HTML"""
        try:
            # Buscar patrones comunes de definición de M.cfg
            patterns = [
                r'M\.cfg\s*=\s*({[^}]+})',  # M.cfg = { ... }
                r'var\s+M\s*=\s*({[^}]+})', # var M = { ... }
                r'M\s*=\s*({[^}]+})',       # M = { ... }
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
                if matches:
                    for match in matches:
                        try:
                            # Intentar parsear el JSON
                            cfg_data = json.loads(match)
                            return cfg_data
                        except json.JSONDecodeError:
                            # Si no es JSON válido, intentar limpiar y parsear
                            cleaned = self.clean_json_string(match)
                            try:
                                cfg_data = json.loads(cleaned)
                                return cfg_data
                            except:
                                continue
            
            # Buscar variables individuales de M.cfg
            m_cfg_vars = {}
            var_patterns = {
                'wwwroot': r'M\.cfg\.wwwroot\s*=\s*[\'"]([^\'"]+)',
                'sesskey': r'M\.cfg\.sesskey\s*=\s*[\'"]([^\'"]+)',
                'userid': r'M\.cfg\.userid\s*=\s*(\d+)',
                'theme': r'M\.cfg\.theme\s*=\s*[\'"]([^\'"]+)',
                'lang': r'M\.cfg\.lang\s*=\s*[\'"]([^\'"]+)',
                'version': r'M\.cfg\.version\s*=\s*[\'"]([^\'"]+)',
            }
            
            for var_name, pattern in var_patterns.items():
                match = re.search(pattern, html_content)
                if match:
                    m_cfg_vars[var_name] = match.group(1)
            
            if m_cfg_vars:
                return m_cfg_vars
                
            return None
            
        except Exception as e:
            print(f"[!] Error parseando M.cfg: {str(e)}")
            return None
    
    def clean_json_string(self, json_str):
        """Limpia una cadena para hacerla válida como JSON"""
        # Reemplazar comillas simples por dobles (si es necesario)
        json_str = re.sub(r"'([^']*)':", r'"\1":', json_str)
        json_str = re.sub(r":\s*'([^']*)'", r': "\1"', json_str)
        
        # Manejar valores booleanos y null
        json_str = re.sub(r':\s*true', ': true', json_str)
        json_str = re.sub(r':\s*false', ': false', json_str)
        json_str = re.sub(r':\s*null', ': null', json_str)
        
        return json_str
    
    def display_sensitive_info(self, m_cfg_data):
        """Muestra la información sensible encontrada"""
        print("\n" + "="*50)
        print("INFORMACIÓN SENSIBLE DETECTADA")
        print("="*50)
        
        # Información crítica
        critical_info = {
            'sesskey': 'Clave de Sesión (sesskey)',
            'userid': 'ID de Usuario (userId)',
            'wwwroot': 'URL Base del Sitio',
            'version': 'Versión de Moodle'
        }
        
        for key, description in critical_info.items():
            if key in m_cfg_data:
                value = m_cfg_data[key]
                print(f"[CRÍTICO] {description}: {value}")
                
                # Guardar información crítica en archivo separado
                if key in ['sesskey', 'userid']:
                    with open(f"{self.output_dir}/critical_info_{key}.txt", 'w') as f:
                        f.write(f"{description}: {value}\n")
                        f.write(f"Fecha de detección: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Mostrar todas las variables encontradas
        print(f"\n[+] Variables M.cfg encontradas ({len(m_cfg_data)}):")
        for key, value in m_cfg_data.items():
            # Ocultar valores sensibles en la salida general
            if key in ['sesskey', 'userid'] and len(str(value)) > 10:
                print(f"    {key}: [VALOR OCULTO - LONGITUD: {len(str(value))}]")
            else:
                print(f"    {key}: {value}")
    
    def extract_additional_sensitive_data(self, html_content):
        """Extrae otros tipos de información sensible"""
        print("\n[+] Buscando información sensible adicional...")
        
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._