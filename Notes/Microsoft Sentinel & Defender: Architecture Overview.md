# Microsoft Sentinel & Defender Security Stack

## 🛠️ Arquitectura de Seguridad (SIEM + XDR)

| Componente | Tipo | Función Principal | Detalle Técnico |
| :--- | :--- | :--- | :--- |
| **Microsoft Sentinel** | **SIEM / SOAR** | Correlación global de logs y automatización. | **Consume** telemetría mediante conectores de datos. Usa **KQL** para hunting. |
| **Defender for Endpoint** | **EDR** | Protección avanzada de dispositivos (laptops/servidores). | Monitorea procesos, archivos y red. Detecta *Credential Dumping* y movimiento lateral. |
| **Defender for Identity** | **ITDR** | Protección de identidades (On-prem AD). | Analiza el tráfico de controladores de dominio para detectar *Pass-the-Hash* o *Golden Ticket*. |
| **Defender for Cloud** | **CSPM** | Postura de seguridad en la nube (Azure/AWS/GCP). | Identifica recursos mal configurados y vulnerabilidades en la infraestructura. |

---

## 🔍 Ejemplo de Telemetría y Threat Hunting (KQL)

Para demostrar cómo Sentinel consume la telemetría de estos componentes, a continuación presento una consulta básica en **Kusto Query Language (KQL)** para identificar procesos sospechosos reportados por el EDR:

```kql
// Buscar procesos sospechosos de Powershell descargando contenido
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Net.WebClient", "DownloadString", "IEX")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
| take 10
