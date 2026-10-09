

#!/usr/bin/env python3

import sys
import json
import asyncio
 
import yaml
import requests
import aiohttp
 
CONTROLLER_IP = "127.0.0.1"
PORT = "8080"
PROTO = {"TCP": ("0x06", "tcp"), "UDP": ("0x11", "udp")}
 
 
# ----------------------------------------------------------------- Clases
class Student:
    def __init__(self, name, mac):
        self.name = name
        self.mac = str(mac).lower()
 
 
class Service:
    def __init__(self, name, protocol, port):
        self.name = name
        self.protocol = protocol.upper()
        self.port = int(port)
 
 
class Server:
    def __init__(self, name, ip, services):
        self.name = name
        self.ip = ip
        self.services = [Service(s["name"], s["protocol"], s["port"])
                         if isinstance(s, dict) else s for s in services]
 
    def get_service(self, name):
        for s in self.services:
            if s.name == name:
                return s
        return None
 
 
class Course:
    def __init__(self, name, state, students, servers, code=None):
        self.name = name
        self.state = state
        self.code = code
        self.students = list(students)   # nombres de alumnos
        self.servers = list(servers)     # [{name, allowed_services}]
 
    def add_student(self, student_name):
        if student_name not in self.students:
            self.students.append(student_name)
 
    def remove_student(self, student_name):
        if student_name in self.students:
            self.students.remove(student_name)
 
    def allows(self, server_name, service_name):
        for sv in self.servers:
            if sv["name"] == server_name and service_name in sv.get("allowed_services", []):
                return True
        return False
 
 
class Connection:
    def __init__(self, handler, student, server, service, flows):
        self.handler = handler
        self.student = student
        self.server = server
        self.service = service
        self.flows = flows  # lista de nombres de flows
 
 
# ------------------------------------------------------ Carga / exportación
def load_data(filename):
    with open(filename, "r") as file:
        data = yaml.safe_load(file)
    students = [Student(x["name"], x["mac"]) for x in data["students"]]
    servers = [Server(y["name"], y["ip"], y["services"]) for y in data["servers"]]
    courses = [Course(z["name"], z["state"], z["students"], z["servers"], z.get("code"))
               for z in data["courses"]]
    return students, servers, courses
 
 
def export_data(filename, students, servers, courses):
    data = {
        "students": [{"name": s.name, "mac": s.mac} for s in students],
        "courses": [{"name": c.name, "code": c.code, "state": c.state,
                     "students": c.students, "servers": c.servers} for c in courses],
        "servers": [{"name": sv.name, "ip": sv.ip,
                     "services": [{"name": x.name, "protocol": x.protocol, "port": x.port}
                                  for x in sv.services]} for sv in servers],
    }
    with open(filename, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
 
 
# ------------------------------------------------------ API de Floodlight
def get_attachment_point(controller_ip, mac):
    endpoint = '/wm/device/'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(
        url,
        params={'mac': mac}
    )
    result, = response.json()
    attachment_points = result.get("attachmentPoint", [])
 
    if not attachment_points:
        return None, None
 
    attachment_point, = attachment_points
    return attachment_point["switchDPID"], attachment_point["port"]
 
 
def get_route(controller_ip, src_mac, dst_mac):
    src_sw_dpid, src_sw_port = get_attachment_point(controller_ip, src_mac)
    dst_sw_dpid, dst_sw_port = get_attachment_point(controller_ip, dst_mac)
    endpoint = f'/wm/topology/route/{src_sw_dpid}/{src_sw_port}/{dst_sw_dpid}/{dst_sw_port}/json'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url)
    return response.json()
 
 
def get_device(controller_ip, **params):
    """Devuelve el primer dispositivo conocido por el controlador (o None)."""
    url = f"http://{controller_ip}:{PORT}/wm/device/"
    devices = requests.get(url, params=params, timeout=5).json()
    return devices[0] if devices else None
 
 
def port_num(p):
    return p["portNumber"] if isinstance(p, dict) else p
 
 
# --------------------------------------------------------- Flows (async)
def _flows_for_hop(handler, idx, dpid, in_p, out_p, c):
    """Genera los 4 flows de un switch: IP ida, IP vuelta, ARP ida, ARP vuelta."""
    ip_proto, l4 = PROTO[c["proto"]]
    base = {"switch": dpid, "priority": "32768", "active": "true"}
    return [
        dict(base, name=f"{handler}_s{idx}_ip_fwd", in_port=str(in_p),
             eth_type="0x0800", eth_src=c["src_mac"], eth_dst=c["dst_mac"],
             ipv4_src=c["src_ip"], ipv4_dst=c["dst_ip"], ip_proto=ip_proto,
             **{f"{l4}_dst": str(c["port"])}, actions=f"output={out_p}"),
        dict(base, name=f"{handler}_s{idx}_ip_rev", in_port=str(out_p),
             eth_type="0x0800", eth_src=c["dst_mac"], eth_dst=c["src_mac"],
             ipv4_src=c["dst_ip"], ipv4_dst=c["src_ip"], ip_proto=ip_proto,
             **{f"{l4}_src": str(c["port"])}, actions=f"output={in_p}"),
        dict(base, name=f"{handler}_s{idx}_arp_fwd", in_port=str(in_p),
             eth_type="0x0806", eth_src=c["src_mac"], arp_tpa=c["dst_ip"],
             actions=f"output={out_p}"),
        dict(base, name=f"{handler}_s{idx}_arp_rev", in_port=str(out_p),
             eth_type="0x0806", eth_src=c["dst_mac"], arp_tpa=c["src_ip"],
             actions=f"output={in_p}"),
    ]
 
 
async def _push(session, url, flow):
    async with session.post(url, json=flow) as resp:
        return flow["name"], resp.status, await resp.text()
 
 
async def _push_all(controller_ip, flows):
    url = f"http://{controller_ip}:{PORT}/wm/staticflowpusher/json"
    async with aiohttp.ClientSession() as session:
        return await asyncio.gather(*(_push(session, url, f) for f in flows))
 
 
async def _delete(session, url, name):
    async with session.delete(url, json={"name": name}) as resp:
        return name, resp.status
 
 
async def _delete_all(controller_ip, names):
    url = f"http://{controller_ip}:{PORT}/wm/staticflowpusher/json"
    async with aiohttp.ClientSession() as session:
        return await asyncio.gather(*(_delete(session, url, n) for n in names))
 
 
def build_route(controller_ip, route, conn_info):
    """Recibe la ruta (get_route) y los datos de la conexión; inserta los flows.
    Devuelve la lista de nombres de flows insertados."""
    hops = [(h["switch"], port_num(h["port"])) for h in route]
    flows = []
    for i in range(0, len(hops) - 1, 2):
        dpid, in_p = hops[i]
        _, out_p = hops[i + 1]
        flows += _flows_for_hop(conn_info["handler"], i // 2, dpid, in_p, out_p, conn_info)
    results = asyncio.run(_push_all(controller_ip, flows))
    for name, status, text in results:
        if status != 200:
            print(f"  ! Error insertando {name}: {status} {text}")
    return [f["name"] for f in flows]
 
 
# ------------------------------------------------------------ Estado app
students, servers, courses, connections = [], [], [], {}
handler_counter = 0
 
 
def find(items, name):
    for x in items:
        if x.name == name:
            return x
    return None
 
 
def is_authorized(student, server, service):
    for c in courses:
        if (c.state == "ACTIVE" and student.name in c.students
                and c.allows(server.name, service.name)):
            return True
    return False
 
 
# ---------------------------------------------------------------- Menús
def ask(msg):
    return input(msg).strip()
 
 
def menu_importar():
    f = ask("Nombre de archivo YAML a importar [database.yaml]: ") or "database.yaml"
    global students, servers, courses
    try:
        students, servers, courses = load_data(f)
        print("Datos importados.")
    except Exception as e:
        print("Error al importar:", e)
 
 
def menu_exportar():
    f = ask("Nombre de archivo YAML a exportar [export.yaml]: ") or "export.yaml"
    export_data(f, students, servers, courses)
    print("Datos exportados a", f)
 
 
def menu_cursos():
    print("1) Listar  2) Mostrar detalles  3) Gestionar alumnos  0) Volver")
    op = ask("> ")
    if op == "1":
        for c in courses:
            print(f"  {c.code} - {c.name} [{c.state}]")
    elif op == "2":
        c = next((x for x in courses if x.code == ask("Código del curso: ")), None)
        if not c:
            return print("Curso no encontrado.")
        print(f"  {c.code} - {c.name} [{c.state}]")
        print("  Alumnos:", ", ".join(c.students) or "(ninguno)")
        for sv in c.servers:
            print(f"  Servidor {sv['name']}: servicios {sv.get('allowed_services', [])}")
    elif op == "3":
        c = next((x for x in courses if x.code == ask("Código del curso: ")), None)
        if not c:
            return print("Curso no encontrado.")
        acc = ask("a) agregar  b) eliminar: ").lower()
        name = ask("Nombre del alumno: ")
        if not find(students, name):
            return print("El alumno no existe.")
        if acc == "a":
            c.add_student(name)
            print("Alumno agregado al curso.")
        elif acc == "b":
            c.remove_student(name)
            print("Alumno eliminado del curso.")
 
 
def menu_alumnos():
    print("1) Crear  2) Listar  3) Mostrar detalles  0) Volver")
    op = ask("> ")
    if op == "1":
        name = ask("Nombre: ")
        mac = ask("MAC: ")
        students.append(Student(name, mac))
        print("Alumno creado.")
    elif op == "2":
        code = ask("Filtrar por código de curso (Enter = todos): ")
        if code:
            c = next((x for x in courses if x.code == code), None)
            if not c:
                return print("Curso no encontrado.")
            for n in c.students:
                print("  ", n)
        else:
            for s in students:
                print("  ", s.name)
    elif op == "3":
        s = find(students, ask("Nombre del alumno: "))
        if not s:
            return print("Alumno no encontrado.")
        print(f"  Nombre: {s.name}\n  MAC: {s.mac}")
        print("  Cursos:", [c.code for c in courses if s.name in c.students])
 
 
def menu_servidores():
    print("1) Listar  2) Mostrar servicios  3) Cursos con acceso a un servicio  0) Volver")
    op = ask("> ")
    if op == "1":
        for sv in servers:
            print(f"  {sv.name}  {sv.ip}")
    elif op == "2":
        sv = find(servers, ask("Nombre del servidor: "))
        if not sv:
            return print("Servidor no encontrado.")
        print(f"  {sv.name} ({sv.ip})")
        for x in sv.services:
            print(f"    {x.name}  {x.protocol}/{x.port}")
    elif op == "3":
        sv_name = ask("Servidor: ")
        svc = ask("Servicio: ")
        res = [c for c in courses if c.allows(sv_name, svc)]
        for c in res:
            print(f"  {c.code} - {c.name} [{c.state}]")
        if not res:
            print("  Ningún curso tiene acceso.")
 
 
def menu_conexiones():
    global handler_counter
    print("1) Crear  2) Listar  3) Borrar  0) Volver")
    op = ask("> ")
    if op == "1":
        s = find(students, ask("Alumno: "))
        sv = find(servers, ask("Servidor: "))
        if not s or not sv:
            return print("Alumno o servidor no encontrado.")
        svc = sv.get_service(ask("Servicio: "))
        if not svc:
            return print("Servicio no encontrado en ese servidor.")
        if not is_authorized(s, sv, svc):
            return print("ERROR: el alumno NO está autorizado a ese servicio.")
        try:
            d_src = get_device(CONTROLLER_IP, mac=s.mac)
            d_dst = get_device(CONTROLLER_IP, ipv4=sv.ip)
            if not d_src or not d_dst or not d_src.get("ipv4"):
                return print("ERROR: el controlador aún no detecta al host del alumno "
                             "o al servidor. Haz un ping entre ambos hosts primero.")
            route = get_route(CONTROLLER_IP, s.mac, d_dst["mac"][0])
            if not route:
                return print("ERROR: el controlador no devolvió ruta.")
        except Exception as e:
            return print("ERROR consultando al controlador:", e)
        handler_counter += 1
        handler = f"conn{handler_counter}"
        info = {"handler": handler, "src_mac": s.mac, "src_ip": d_src["ipv4"][0],
                "dst_mac": d_dst["mac"][0], "dst_ip": sv.ip,
                "proto": svc.protocol, "port": svc.port}
        flows = build_route(CONTROLLER_IP, route, info)
        connections[handler] = Connection(handler, s, sv, svc, flows)
        print(f"Conexión creada. Handler: {handler} ({len(flows)} flows)")
    elif op == "2":
        for h, c in connections.items():
            print(f"  {h}: {c.student.name} -> {c.server.name}:{c.service.name} "
                  f"({len(c.flows)} flows)")
        if not connections:
            print("  (no hay conexiones)")
    elif op == "3":
        h = ask("Handler de la conexión: ")
        c = connections.get(h)
        if not c:
            return print("Handler no encontrado.")
        asyncio.run(_delete_all(CONTROLLER_IP, c.flows))
        del connections[h]
        print("Conexión eliminada.")
 
 
def menu():
    print("\n=== MENÚ PRINCIPAL ===")
    print("1) Importar\n2) Exportar\n3) Cursos\n4) Alumnos\n"
          "5) Servidores\n6) Conexiones\n0) Salir")
    return ask("> ")
 
 
def main():
    global CONTROLLER_IP, students, servers, courses
    if len(sys.argv) > 1:
        CONTROLLER_IP = sys.argv[1]
    students, servers, courses = load_data("database.yaml")
    print(f"Datos cargados. Controlador: {CONTROLLER_IP}:{PORT}")
    acciones = {"1": menu_importar, "2": menu_exportar, "3": menu_cursos,
                "4": menu_alumnos, "5": menu_servidores, "6": menu_conexiones}
    while True:
        op = menu()
        if op == "0":
            break
        acciones.get(op, lambda: print("Opción inválida."))()
 
 
if __name__ == "__main__":
    main()
 

