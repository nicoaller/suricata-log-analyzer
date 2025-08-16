
import sys
from sly import Lexer, Parser
import xml.dom.minidom as minidom

# ---------------------------
# Funciones de utilidad
# ---------------------------
def clean_value(value):
    """
    Elimina todas las comillas de una cadena.

    Parámetros:
        value (str): Cadena de entrada.

    Retorna:
        str: Cadena sin comillas.
    """
    return "".join(char for char in value if char != '"')


# ===========================
# Sublexer de Fechas (TimestampLexer)
# ===========================
class TimestampLexer(Lexer):
    """
    Sublexer encargado de procesar y descomponer un timestamp en formato ISO 8601.
    Extrae año, mes, día, hora, minuto, segundo, milisegundos y zona horaria.
    """
    tokens = { YEAR, MONTH, DAY, HOUR, MINUTE, SECOND, MILLISECOND, TIMEZONE }
    ignore = ' \t'  # Ignora espacios y tabulaciones

    # Expresiones regulares para cada componente del timestamp
    YEAR        = r'"\d{4}(?=-)'                   # Año con 4 dígitos, seguido de '-'
    MONTH       = r'\d{2}(?=-)'                    # Mes con 2 dígitos, seguido de '-'
    DAY         = r'\d{2}(?=T)'                    # Día con 2 dígitos, seguido de 'T'
    HOUR        = r'(?<=T)\d{2}(?=:)'              # Hora después de 'T', antes de ':'
    MINUTE      = r'\d{2}(?=:)'                    # Minuto antes de ':'
    SECOND      = r'\d{2}(?=\.)'                   # Segundo antes de '.'
    MILLISECOND = r'\d+'                           # Milisegundos, uno o más dígitos
    TIMEZONE    = r'[+\-]\d{4}"'                   # Zona horaria con formato ±hhmm"

    def error(self, t):
        """
        Maneja errores de reconocimiento de tokens.
        Ignora los caracteres separadores del timestamp.
        """
        if t.value[0] in "-:.T":
            self.index += 1  # Avanza el análisis sin lanzar error
            return None
        raise Exception(f"Carácter no permitido '{t.value[0]}' en posición {t.index}")

    # Métodos para procesar cada token y almacenarlos temporalmente
    def YEAR(self, t):        self._add_part("year", clean_value(t.value))
    def MONTH(self, t):       self._add_part("month", int(t.value))
    def DAY(self, t):         self._add_part("day", int(t.value))
    def HOUR(self, t):        self._add_part("hour", int(t.value))
    def MINUTE(self, t):      self._add_part("minute", int(t.value))
    def SECOND(self, t):      self._add_part("second", int(t.value))
    def MILLISECOND(self, t): self._add_part("ms", t.value)

    def TIMEZONE(self, t):
        """
        Finaliza el reconocimiento del timestamp, lo formatea y lo guarda.
        Retorna un token STRING con el valor formateado.
        """
        zona = clean_value(t.value)
        self._add_part("tz", zona)

        # Construcción del timestamp formateado
        partes = dict(self.current_timestamp_data)
        texto = f"{partes['day']}/{partes['month']}/{partes['year']} - {partes['hour']}:{partes['minute']}:{partes['second']} UTC {partes['tz']}"

        self.current_data["timestamp"] = texto  # Se guarda en los datos actuales
        self.current_timestamp_data.clear()    # Se limpia para el siguiente timestamp
        self.begin(LogLexer)                   # Se vuelve al lexer principal

        t.type = 'STRING'
        t.value = texto
        return t

    def _add_part(self, clave, valor):
        """
        Añade una parte del timestamp a la lista temporal.
        Convierte el valor a entero si es numérico.
        """
        self.current_timestamp_data.append((clave, int(valor) if isinstance(valor, str) and valor.isdigit() else valor))


# ===========================
# Sublexer de Puertos (PortLexer)
# ===========================
class PortLexer(Lexer):
    """
    Sublexer encargado de clasificar puertos como privilegiados o no privilegiados.
    """
    tokens = { PORT_PRIVILEGED, PORT_NON_PRIVILEGED }
    ignore = ' \t'  # Ignora espacios y tabulaciones

    # Puerto no privilegiado: en el rango 1024–65535
    PORT_NON_PRIVILEGED = (
        r'\b(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|'
        r'[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b'
    )

    # Puerto privilegiado: en el rango 0–1023
    PORT_PRIVILEGED = r'\b([0-9]{1,3}|10[0-1][0-9]|102[0-3])\b'

    def PORT_PRIVILEGED(self, t):
        """
        Procesa un puerto privilegiado.
        """
        self._assign_port(t, "privileged")
        return t

    def PORT_NON_PRIVILEGED(self, t):
        """
        Procesa un puerto no privilegiado.
        """
        self._assign_port(t, "non-privileged")
        return t

    def _assign_port(self, t, tipo):
        """
        Guarda el número de puerto y su tipo en los datos actuales.
        """
        campo = self.current_field
        if campo in {"src_port", "dest_port"}:
            self.current_data[campo] = (t.value, tipo)
        self.current_field = None
        self.begin(LogLexer)
        t.type = 'NUMBER'


# ===========================
# Sublexer de IPs (IpLexer)
# ===========================
class IpLexer(Lexer):
    """
    Sublexer encargado de reconocer y clasificar direcciones IP como públicas o privadas.
    """
    tokens = { IP_PRIVATE, IP_PUBLIC }
    ignore = ' \t'  # Ignora espacios y tabulaciones

    # IP privada: rangos reservados según RFC1918
    IP_PRIVATE = (
        r'"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|'
        r'192\.168\.\d{1,3}\.\d{1,3})"'
    )

    # IP pública: cualquier otra IP que no sea privada
    IP_PUBLIC = (
        r'"(?!10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'
    )

    def IP_PRIVATE(self, t):
        """
        Procesa una dirección IP privada.
        """
        return self._handle_ip(t, "private")

    def IP_PUBLIC(self, t):
        """
        Procesa una dirección IP pública.
        """
        return self._handle_ip(t, "public")

    def _handle_ip(self, t, tipo):
        """
        Guarda la IP procesada en el campo correspondiente del diccionario actual
        y retorna el control al lexer principal.

        Parámetros:
            t (Token): Token que contiene la IP.
            tipo (str): Tipo de IP ("private" o "public").

        Retorna:
            Token procesado con tipo STRING y valor limpio.
        """
        ip = clean_value(t.value)  # Elimina comillas
        campo = self.current_field  # Campo actual en procesamiento
        if campo in {"src_ip", "dest_ip"}:
            self.current_data[campo] = (ip, tipo)  # Guarda IP y su tipo
        self.current_field = None  # Limpia el campo actual
        self.begin(LogLexer)  # Vuelve al lexer principal
        t.type = 'STRING'
        t.value = ip
        return t


# ===========================
# Lexer Principal (LogLexer)
# ===========================
class LogLexer(Lexer):
    """
    Lexer principal que reconoce tokens de un log JSON de Suricata.
    Redirige a sublexers cuando detecta campos especiales como IPs, puertos o timestamp.
    """
    tokens = {
        STRING, NUMBER, BOOL, NULL, NEWLINE,
        LBRACE, RBRACE, LBRACKET, RBRACKET, COLON, COMMA,
        EVENT_TYPE, SIGNATURE_ID, SIGNATURE, CATEGORY, SEVERITY,
        SRC_IP, DEST_IP, SRC_PORT, DEST_PORT, TIMESTAMP
    }

    ignore = ' \t'  # Ignora espacios y tabulaciones

    # ----------- Tokens básicos -----------

    NUMBER   = r'\d+(\.\d+)?'              # Números enteros o flotantes
    BOOL     = r'true|false'               # Booleanos en JSON
    NULL     = r'null'                     # Nulo en JSON
    NEWLINE  = r'\n+'                      # Salto de línea (se usa como separador entre eventos)

    # ----------- Símbolos JSON -----------

    LBRACE   = r'\{'                       # Llave izquierda
    RBRACE   = r'\}'                       # Llave derecha
    LBRACKET = r'\['                       # Corchete izquierdo
    RBRACKET = r'\]'                       # Corchete derecho
    COLON    = r':'                        # Dos puntos (separador clave:valor)
    COMMA    = r','                        # Coma (separador de elementos)

    # ----------- Palabras clave de campos -----------

    EVENT_TYPE   = r'"event_type"'         # Campo "event_type"
    SIGNATURE_ID = r'"signature_id"'       # Campo "signature_id"
    SIGNATURE    = r'"signature"'          # Campo "signature"
    CATEGORY     = r'"category"'           # Campo "category"
    SEVERITY     = r'"severity"'           # Campo "severity"
    SRC_IP       = r'"src_ip"'             # Campo "src_ip"
    DEST_IP      = r'"dest_ip"'            # Campo "dest_ip"
    SRC_PORT     = r'"src_port"'           # Campo "src_port"
    DEST_PORT    = r'"dest_port"'          # Campo "dest_port"
    TIMESTAMP    = r'"timestamp"'          # Campo "timestamp"

    # Cadenas entre comillas
    STRING   = r'"(?:\\.|[^"\\])*"'

    def __init__(self):
        """
        Inicializa los contadores, listas y estructuras auxiliares para el análisis.
        """
        self.event_count = {}               # Conteo por tipo de evento
        self.alerts_info = {}              # Información de alertas agrupadas por signature_id
        self.current_data = {}             # Diccionario temporal con datos del evento actual
        self.events = []                   # Lista de eventos procesados
        self.current_timestamp_data = []  # Temporal para partes del timestamp
        self.current_field = None         # Campo que se está procesando en este momento

    # ========== Manejo de campos clave ==========
    def EVENT_TYPE(self, t):   return self._set_field(t, "event_type")
    def SIGNATURE_ID(self, t): return self._set_field(t, "signature_id")
    def SIGNATURE(self, t):    return self._set_field(t, "signature")
    def CATEGORY(self, t):     return self._set_field(t, "category")
    def SEVERITY(self, t):     return self._set_field(t, "severity")
    def SRC_IP(self, t):       return self._set_field(t, "src_ip")
    def DEST_IP(self, t):      return self._set_field(t, "dest_ip")
    def SRC_PORT(self, t):     return self._set_field(t, "src_port")
    def DEST_PORT(self, t):    return self._set_field(t, "dest_port")
    def TIMESTAMP(self, t):    return self._set_field(t, "timestamp")

    def _set_field(self, t, name):
        """
        Establece el nombre del campo actual para asignar el próximo valor leído.

        Parámetros:
            t (Token): Token correspondiente al nombre del campo.
            name (str): Nombre limpio del campo (sin comillas).
        """
        self.current_field = name
        t.value = name
        return t

    # ========== Tokens con valor ==========

    def STRING(self, t):
        """
        Procesa un valor tipo cadena.
        Asigna el valor al campo actual si hay uno en espera.
        """
        texto = t.value[1:-1]  # Elimina las comillas externas
        if self.current_field:
            self.current_data[self.current_field] = texto
            self.current_field = None
        t.value = texto
        return t

    def NUMBER(self, t):
        """
        Procesa un valor numérico, ya sea entero o flotante.
        """
        valor = float(t.value) if '.' in t.value else int(t.value)
        if self.current_field:
            self.current_data[self.current_field] = valor
            self.current_field = None
        t.value = valor
        return t

    def BOOL(self, t):
        """
        Procesa un valor booleano (true o false).
        """
        booleano = (t.value == "true")
        if self.current_field:
            self.current_data[self.current_field] = booleano
            self.current_field = None
        t.value = booleano
        return t

    def NULL(self, t):
        """
        Procesa un valor nulo.
        """
        if self.current_field:
            self.current_data[self.current_field] = None
            self.current_field = None
        t.value = None
        return t

    def NEWLINE(self, t):
        """
        Procesa el fin de una línea de log (evento).
        Copia los datos actuales y los limpia para el siguiente evento.
        """
        t.value = self.current_data.copy()
        self.current_data.clear()
        return t

    # ========== Cambio a sublexers ==========

    def COLON(self, t):
        """
        Detecta campos especiales que requieren sublexers y transfiere el control al correspondiente.
        """
        campo = self.current_field

        if campo == "timestamp":
            self.begin(TimestampLexer)
        elif campo in {"src_ip", "dest_ip"}:
            self.begin(IpLexer)
        elif campo in {"src_port", "dest_port"}:
            self.begin(PortLexer)
        elif campo not in {
            "event_type", "signature", "signature_id", "category", "severity"
        }:
            # Si el campo no es relevante, se descarta para no almacenar su valor
            self.current_field = None
        return t


class LogParser(Parser):
    """
    Parser encargado de procesar los eventos extraídos por el lexer y generar
    estadísticas y agrupaciones relevantes de los datos de los logs.
    """
    tokens = LogLexer.tokens  # Usa los mismos tokens definidos en el LogLexer

    def __init__(self):
        """
        Inicializa las estructuras internas necesarias para el análisis de eventos.
        """
        self.errors = []             # Lista para almacenar errores de análisis (si se implementan)
        self.events = []             # Lista de todos los eventos parseados
        self.event_count = dict()    # Diccionario de conteo de eventos por tipo
        self.alerts_info = dict()    # Diccionario con la información agrupada por signature_id

    def handle_event(self, data, lexer_data):
        """
        Procesa un evento individual, actualizando estadísticas generales y agrupaciones de alertas.

        Parámetros:
            data (dict): Evento ya procesado por el parser (estructura JSON).
            lexer_data (dict): Datos originales obtenidos del lexer (NEWLINE.value).
        """
        self.events.append(data)  # Se añade el evento a la lista general

        # Conteo de eventos por tipo
        event_type = data.get("event_type")
        if event_type:
            self.event_count[event_type] = self.event_count.get(event_type, 0) + 1

        # Si el evento es una alerta, se agrupa por signature_id
        if event_type == "alert":
            alert = data.get("alert", {})
            sid = alert.get("signature_id")
            if sid is None:
                return  # Si no hay ID de firma, se ignora la alerta

            # Si es la primera vez que se ve este signature_id, se inicializa la estructura
            if sid not in self.alerts_info:
                self.alerts_info[sid] = {
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),

                    "src_ips_public": set(),
                    "src_ips_private": set(),
                    "dest_ips_public": set(),
                    "dest_ips_private": set(),
                    "src_ports_privileged": set(),
                    "src_ports_non_privileged": set(),
                    "dest_ports_privileged": set(),
                    "dest_ports_non_privileged": set(),

                    "events": []
                }

            info = self.alerts_info[sid]

            # Clasificación de IPs fuente y destino como públicas o privadas
            for field, pub_key, priv_key in [
                ("src_ip", "src_ips_public", "src_ips_private"),
                ("dest_ip", "dest_ips_public", "dest_ips_private")
            ]:
                val = lexer_data.get(field)
                if isinstance(val, tuple):
                    ip, kind = val
                    if kind == "public":
                        info[pub_key].add(ip)
                    elif kind == "private":
                        info[priv_key].add(ip)

            # Clasificación de puertos fuente y destino como privilegiados o no privilegiados
            for field, priv_key, non_priv_key in [
                ("src_port", "src_ports_privileged", "src_ports_non_privileged"),
                ("dest_port", "dest_ports_privileged", "dest_ports_non_privileged")
            ]:
                val = lexer_data.get(field)
                if isinstance(val, tuple):
                    port, kind = val
                    if kind == "privileged":
                        info[priv_key].add(str(port))
                    elif kind == "non-privileged":
                        info[non_priv_key].add(str(port))

            # Añadir el evento al listado de eventos de esta firma
            info["events"].append(data)

    def generate_output(self):
        """
        Imprime por pantalla el resumen de eventos procesados y la información agrupada por firma.
        """
        print("\nConteo de eventos por tipo:")
        for etype, count in self.event_count.items():
            print(f" - {etype}: {count} eventos")

        print("\nInformación agrupada por firma de alerta:")
        for sid, info in self.alerts_info.items():
            print(f"\nSignature ID: {sid}")
            print(f"Signature: {info['signature']}")
            print(f"Category: {info['category']}")
            print(f"Severity: {info['severity']}")
            print(f"Total de eventos: {len(info['events'])}")

            print(f"Source IPs Públicas: {', '.join(sorted(info['src_ips_public'])) or 'Ninguna'}")
            print(f"Source IPs Privadas: {', '.join(sorted(info['src_ips_private'])) or 'Ninguna'}")
            print(f"Destination IPs Públicas: {', '.join(sorted(info['dest_ips_public'])) or 'Ninguna'}")
            print(f"Destination IPs Privadas: {', '.join(sorted(info['dest_ips_private'])) or 'Ninguna'}")
            print(f"Source Ports Privileged: {', '.join(sorted(info['src_ports_privileged'])) or 'Ninguno'}")
            print(f"Source Ports Non-Privileged: {', '.join(sorted(info['src_ports_non_privileged'])) or 'Ninguno'}")
            print(f"Destination Ports Privileged: {', '.join(sorted(info['dest_ports_privileged'])) or 'Ninguno'}")
            print(f"Destination Ports Non-Privileged: {', '.join(sorted(info['dest_ports_non_privileged'])) or 'Ninguno'}")


    def generate_xml(self):
        """
        Genera un documento XML estructurado con los resultados del análisis.
        Incluye un resumen de eventos y alertas agrupadas por firma, así como
        un listado completo de todos los eventos individuales procesados.
        """
        doc = minidom.Document()
        root = doc.createElement("suricata")  # Nodo raíz del XML
        doc.appendChild(root)

        # Sección de resumen general
        summary = doc.createElement("summary")
        root.appendChild(summary)

        # Sub-sección con el conteo de eventos por tipo
        types = doc.createElement("types")
        summary.appendChild(types)
        for etype, count in self.event_count.items():
            node = doc.createElement(etype)  # Etiqueta con nombre del tipo de evento
            node.appendChild(doc.createTextNode(str(count)))  # Número de eventos
            types.appendChild(node)

        # Sub-sección con alertas agrupadas por signature_id
        alerts = doc.createElement("alerts")
        summary.appendChild(alerts)

        for sid, info in self.alerts_info.items():
            alert_node = doc.createElement("alert")
            alert_node.setAttribute("signature_id", str(sid))
            alert_node.setAttribute("signature", info["signature"])
            alert_node.setAttribute("category", info["category"])
            alert_node.setAttribute("severity", str(info["severity"]))

            # Número total de eventos asociados a esta alerta
            count = doc.createElement("count")
            count.appendChild(doc.createTextNode(str(len(info["events"]))))
            alert_node.appendChild(count)

            def append_ip_list(parent, tag, values, ip_type):
                """
                Añade una lista de IPs o puertos a un nodo XML.
                
                Parámetros:
                    parent (Element): Nodo padre al que se añadirán los hijos.
                    tag (str): Nombre de la etiqueta a crear (ip o port).
                    values (set): Conjunto de valores a agregar.
                    ip_type (str): Tipo del atributo (private/public/privileged/unprivileged).
                """
                for val in sorted(values):
                    node = doc.createElement(tag)
                    node.setAttribute("type", ip_type)
                    node.appendChild(doc.createTextNode(val))
                    parent.appendChild(node)

            # Añadir IPs de origen
            src_ips = doc.createElement("src_ips")
            append_ip_list(src_ips, "ip", info["src_ips_private"], "private")
            append_ip_list(src_ips, "ip", info["src_ips_public"], "public")
            alert_node.appendChild(src_ips)

            # Añadir puertos de origen
            src_ports = doc.createElement("src_ports")
            append_ip_list(src_ports, "port", info["src_ports_privileged"], "privileged")
            append_ip_list(src_ports, "port", info["src_ports_non_privileged"], "unprivileged")
            alert_node.appendChild(src_ports)

            # Añadir IPs de destino
            dest_ips = doc.createElement("dest_ips")
            append_ip_list(dest_ips, "ip", info["dest_ips_private"], "private")
            append_ip_list(dest_ips, "ip", info["dest_ips_public"], "public")
            alert_node.appendChild(dest_ips)

            # Añadir puertos de destino
            dest_ports = doc.createElement("dest_ports")
            append_ip_list(dest_ports, "port", info["dest_ports_privileged"], "privileged")
            append_ip_list(dest_ports, "port", info["dest_ports_non_privileged"], "unprivileged")
            alert_node.appendChild(dest_ports)

            # Nodo que contiene todos los eventos individuales relacionados con la alerta
            events_node = doc.createElement("events")
            for e in info["events"]:
                e_node = doc.createElement("event")

                def append_field(tag, value):
                    """
                    Añade un campo simple (etiqueta con texto) a un nodo de evento.

                    Parámetros:
                        tag (str): Nombre de la etiqueta.
                        value: Contenido textual del campo.
                    """
                    field_node = doc.createElement(tag)
                    field_node.appendChild(doc.createTextNode(str(value)))
                    e_node.appendChild(field_node)

                # Agrega campos clave al evento
                append_field("timestamp", e.get("timestamp", ""))
                append_field("event_type", e.get("event_type", ""))
                append_field("src_ip", e.get("src_ip", ""))
                append_field("src_port", e.get("src_port", ""))
                append_field("dest_ip", e.get("dest_ip", ""))
                append_field("dest_port", e.get("dest_port", ""))
                append_field("signature_id", sid)
                append_field("signature", info.get("signature", ""))
                append_field("category", info.get("category", ""))
                append_field("severity", info.get("severity", ""))

                events_node.appendChild(e_node)

            alert_node.appendChild(events_node)
            alerts.appendChild(alert_node)

        # Sección independiente que contiene todos los eventos, no solo alertas
        all_events_node = doc.createElement("events")
        root.appendChild(all_events_node)

        def build_xml_node(parent, key, value):
            """
            Crea recursivamente nodos XML a partir de estructuras anidadas tipo dict o list.
            
            Parámetros:
                parent (Element): Nodo al que se añadirá el nuevo hijo.
                key (str): Nombre de la etiqueta.
                value: Valor asociado (puede ser dict, list o valor simple).
            """
            if isinstance(value, dict):
                node = doc.createElement(key)
                for k, v in value.items():
                    build_xml_node(node, k, v)
                parent.appendChild(node)
            elif isinstance(value, list):
                node = doc.createElement(key)
                for item in value:
                    build_xml_node(node, "item", item)
                parent.appendChild(node)
            else:
                node = doc.createElement(key)
                node.appendChild(doc.createTextNode(str(value)))
                parent.appendChild(node)

        # Añadir todos los eventos del log completo
        for e in self.events:
            event_node = doc.createElement("event")
            for key, val in e.items():
                build_xml_node(event_node, str(key), val)
            all_events_node.appendChild(event_node)

        # Guardar el documento XML en un archivo local
        xml_str = doc.toprettyxml(indent="\t", encoding="utf-8").decode("utf-8")
        with open("output.xml", "w", encoding="utf-8") as f:
            f.write(xml_str)


    @_('events')
    def s(self, p):
        """
        Regla inicial del parser (símbolo de inicio).
        Recibe la lista completa de eventos reconocidos y finaliza el análisis.

        Realiza:
            - Llamada a la función de salida formateada por pantalla.
            - Generación del archivo XML con los resultados.

        Parámetros:
            p (Parser): Contenedor de la producción.

        Retorna:
            list: Lista de eventos parseados.
        """
        self.generate_output()
        self.generate_xml()
        return p.events


    @_('event')
    def events(self, p):
        """
        Caso base de la lista de eventos: lista que contiene un solo evento.

        Parámetros:
            p (Parser): Contenedor con un solo evento.

        Retorna:
            list: Lista con un único evento.
        """
        return [p.event]


    @_('events event')
    def events(self, p):
        """
        Regla recursiva para construir una lista de eventos.

        Cada vez que se detecta un nuevo evento, se añade a la lista previamente construida.

        Parámetros:
            p (Parser): Contiene p.events (lista existente) y p.event (nuevo evento).

        Retorna:
            list: Lista acumulada de eventos.
        """
        return p.events + [p.event]


    @_('json NEWLINE')
    def event(self, p):  
        """
        Regla que reconoce un evento completo seguido de un salto de línea.

        Esta forma permite recuperar los datos adicionales obtenidos por el lexer,
        como la clasificación de IPs y puertos, ya que el token NEWLINE contiene
        una copia del diccionario `current_data` del lexer.

        Parámetros:
            p (Parser): p.json contiene el evento en sí; p.NEWLINE.value tiene lexer_data.

        Retorna:
            dict: Diccionario del evento JSON.
        """
        self.handle_event(p.json, p.NEWLINE)
        return p.json


    @_('json')
    def event(self, p):
        """
        Regla alternativa para reconocer un evento que no termina con salto de línea.

        Útil en casos donde se analiza un objeto JSON aislado.

        Parámetros:
            p (Parser): Contiene el objeto JSON.

        Retorna:
            dict: Evento parseado.
        """
        return p.json


    @_('LBRACE fields RBRACE')
    def json(self, p):
        """
        Reconoce un objeto JSON con uno o más campos internos.

        Sintaxis:
            { campo1: valor1, campo2: valor2, ... }

        Parámetros:
            p (Parser): Contiene lista de pares clave:valor.

        Retorna:
            dict: Diccionario construido a partir de los campos.
        """
        return dict(p.fields)


    @_('LBRACE RBRACE')
    def json(self, p):
        """
        Reconoce un objeto JSON vacío.

        Sintaxis:
            {}

        Retorna:
            dict: Diccionario vacío.
        """
        return {}


    @_('field')
    def fields(self, p):
        """
        Caso base para campos dentro de un objeto JSON.

        Retorna:
            list: Lista con un solo par clave:valor.
        """
        return [p.field]


    @_('fields COMMA field')
    def fields(self, p):
        """
        Construye recursivamente la lista de campos de un objeto JSON.

        Cada campo se representa como un par (clave, valor).

        Parámetros:
            p (Parser): Contiene campos anteriores y uno nuevo.

        Retorna:
            list: Lista extendida de campos.
        """
        return p.fields + [p.field]

    # ====== Campos específicos procesados por sublexers ======

    @_('TIMESTAMP COLON value')
    def field(self, p):
        """
        Procesa el campo "timestamp", que fue manejado por el sublexer TimestampLexer.

        Parámetros:
            p (Parser): Contiene el nombre del campo, el símbolo ':' y su valor.

        Retorna:
            tuple: Par ('timestamp', valor).
        """
        return ('timestamp', p.value)

    @_('SRC_IP COLON value')
    def field(self, p):
        """
        Procesa el campo "src_ip", manejado por el sublexer IpLexer.

        Retorna:
            tuple: Par ('src_ip', valor).
        """
        return ('src_ip', p.value)

    @_('DEST_IP COLON value')
    def field(self, p):
        """
        Procesa el campo "dest_ip", manejado por el sublexer IpLexer.

        Retorna:
            tuple: Par ('dest_ip', valor).
        """
        return ('dest_ip', p.value)

    @_('SRC_PORT COLON value')
    def field(self, p):
        """
        Procesa el campo "src_port", manejado por el sublexer PortLexer.

        Retorna:
            tuple: Par ('src_port', valor).
        """
        return ('src_port', p.value)

    @_('DEST_PORT COLON value')
    def field(self, p):
        """
        Procesa el campo "dest_port", manejado por el sublexer PortLexer.

        Retorna:
            tuple: Par ('dest_port', valor).
        """
        return ('dest_port', p.value)

    # ====== Campos clave con valor directo ======

    @_('EVENT_TYPE COLON value')
    def field(self, p):
        """
        Procesa el campo "event_type".

        Retorna:
            tuple: Par ('event_type', valor).
        """
        return ('event_type', p.value)

    @_('SIGNATURE COLON value')
    def field(self, p):
        """
        Procesa el campo "signature".

        Retorna:
            tuple: Par ('signature', valor).
        """
        return ('signature', p.value)

    @_('SIGNATURE_ID COLON value')
    def field(self, p):
        """
        Procesa el campo "signature_id".

        Retorna:
            tuple: Par ('signature_id', valor).
        """
        return ('signature_id', p.value)

    @_('CATEGORY COLON value')
    def field(self, p):
        """
        Procesa el campo "category".

        Retorna:
            tuple: Par ('category', valor).
        """
        return ('category', p.value)

    @_('SEVERITY COLON value')
    def field(self, p):
        """
        Procesa el campo "severity".

        Retorna:
            tuple: Par ('severity', valor).
        """
        return ('severity', p.value)

    # ====== Regla genérica para cualquier otro campo no especificado ======

    @_('STRING COLON value')
    def field(self, p):
        """
        Regla general para campos no contemplados explícitamente.

        Retorna:
            tuple: Par (nombre_del_campo, valor).
        """
        return (p.STRING, p.value)


    @_('STRING')
    def value(self, p):
        """
        Valor de tipo cadena.

        Retorna:
            str: Valor de cadena.
        """
        return p.STRING

    @_('NUMBER')
    def value(self, p):
        """
        Valor numérico (entero o decimal).

        Retorna:
            int o float: Valor numérico.
        """
        return p.NUMBER

    @_('BOOL')
    def value(self, p):
        """
        Valor booleano (true o false).

        Retorna:
            bool: Valor booleano.
        """
        return p.BOOL

    @_('NULL')
    def value(self, p):
        """
        Valor nulo.

        Retorna:
            None: Representación de valor nulo.
        """
        return None

    @_('array')
    def value(self, p):
        """
        Valor de tipo array (lista JSON).

        Retorna:
            list: Lista de valores.
        """
        return p.array

    @_('json')
    def value(self, p):
        """
        Valor de tipo objeto JSON (estructura anidada).

        Retorna:
            dict: Diccionario anidado.
        """
        return p.json

    @_('LBRACKET values RBRACKET')
    def array(self, p):
        """
        Reconoce un array con uno o más valores.

        Sintaxis:
            [valor1, valor2, ...]

        Retorna:
            list: Lista de valores.
        """
        return p.values

    @_('LBRACKET RBRACKET')
    def array(self, p):
        """
        Reconoce un array vacío.

        Sintaxis:
            []

        Retorna:
            list: Lista vacía.
        """
        return []

    @_('value')
    def values(self, p):
        """
        Caso base: lista con un solo valor.

        Retorna:
            list: Lista con un único elemento.
        """
        return [p.value]

    @_('values COMMA value')
    def values(self, p):
        """
        Construye recursivamente una lista de valores dentro de un array.

        Retorna:
            list: Lista extendida.
        """
        return p.values + [p.value]


    def error(self, p):
        """
        Manejo de errores sintácticos. Registra el tipo de error y la ubicación.

        Parámetros:
            p (Token o None): Token donde ocurrió el error o None si fue al final del archivo.
        """
        if p:
            self.errors.append(f"Syntax error at token {p.type} (value: {p.value})")
        else:
            self.errors.append("Syntax error at EOF")


# No debéis modificar el comportamiento de esta sección
if __name__ == '__main__':

    # Inicializa el Lexer principal.
    lexer = LogLexer()
    # Inicializa el Parser principal.
    parser = LogParser()
    
    # Lee íntegramente el fichero proporcionado por entrada estándar
    # Windows: Get-Content example.txt | python p1.py
    # Unix: python p1.py < example.txt
    text = sys.stdin.read()

    tokens = None
    # Procesa los tokens (análisis léxico) y, posteriormente, redirige
    # su salida al analizador sintáctico para verificar la gramática.

    if text:

        # Para el desarrollo puede ser útil mostrar los tokens procesados
        # antes de pasar al parser. 
        # (dejar comentado para la entrega)
        # for t in lexer.tokenize(text)::
        #     print(t)

        # Importante: El parser debe recibir directamente la salida
        # proporcionada por el lexer (generador)
        parser.parse(lexer.tokenize(text))