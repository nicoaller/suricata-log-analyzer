analyzer.py

Este script implementa un analizador léxico y sintáctico de logs JSON generados por Suricata IDS utilizando la librería SLY.

Funcionalidad:
Lee eventos en formato JSON línea a línea.
Verifica la validez de la estructura.
Identifica y clasifica campos como timestamps, IPs y puertos.
Procesa alertas agrupándolas por signature_id.
Genera salida en consola con estadísticas.
Produce un archivo XML con el listado jerárquico de eventos y un resumen de alertas.

Uso
El script se ejecuta indicando el archivo de entrada (por ejemplo eve.json):
python analyzer.py eve.json
Esto genera un archivo de salida llamado output.xml (o eve.xml) en la ruta definida dentro del código.

Dependencias
Python 3.8 o superior
sly==0.4

Se instalan con:

pip install -r requirements.txt
