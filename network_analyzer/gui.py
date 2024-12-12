#gui.py
import tkinter as tk
import threading
from analyzer import main
from live_plot import LivePlot
from scapy.all import sniff, IP, TCP, UDP, ICMP
from network_utils import analyze_packet
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from tkinter import ttk
from ping3 import ping

class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Analyzer")
        self.root.config(bg="#2E3B4E")  # Fondo oscuro

         # Usamos ttk para botones y etiquetas
        self.style = ttk.Style()
        self.style.configure("TButton",
                             background="#4CAF50", 
                             font=("Arial", 12),
                             padding=10)
        self.style.configure("TLabel", font=("Arial", 12), background="#2E3B4E", foreground="white")
        

        # Configuración del tamaño de la ventana
        self.root.geometry("800x600")

        # Variable de control para el menú
        self.current_frame = None

         # Menú
        self.menu = tk.Menu(root)
        self.root.config(menu=self.menu)

        self.capture_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Opciones", menu=self.capture_menu)
        self.capture_menu.add_command(label="Captura de Paquetes", command=self.show_capture_frame)
        self.capture_menu.add_command(label="Gráficas de Protocolos", command=self.show_graph_frame)
        self.capture_menu.add_command(label="Hacer Ping a Servidor", command=self.show_ping_frame)  


        self.capture_thread = None
        self.running = False

        # Variable de control para los frames
        self.current_frame = None
        self.show_capture_frame()

        # Inicializamos el frame de captura
        self.show_capture_frame()

        # Variables para contar protocolos
        self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Otros": 0}

        self.capture_thread = None
        self.running = False

        self.capture_menu.add_command(label="Apartado Educativo", command=self.show_education_frame)

    def show_capture_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
        
        # Aseguramos que el fondo del Frame también sea negro
        self.current_frame = tk.Frame(self.root, bg="black", bd=2, relief="solid")
        self.current_frame.pack(fill=tk.BOTH, expand=True)

        # Titulo de la sección
        title_label = ttk.Label(self.current_frame, text="Captura de Paquetes", style="TLabel")
        title_label.pack(pady=20)

        # Cuadro de entrada para el filtro de IP/Protocolo
        self.filter_label = ttk.Label(self.current_frame, text="Filtro de IP/Protocolo (Ejemplo: host 192.168.1.1 and tcp)", style="TLabel")
        self.filter_label.pack(pady=5)

        self.filter_entry = ttk.Entry(self.current_frame, width=50)
        self.filter_entry.pack(pady=5)
        self.filter_entry.insert(0, "host 192.168.1.1 and tcp")  # valor por defecto

        self.active_filter_label = ttk.Label(self.current_frame, text="Filtro activo: host 192.168.1.1 and tcp", style="TLabel")
        self.active_filter_label.pack(pady=5)

        # Botones de control
        self.start_button = ttk.Button(self.current_frame, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(pady=10)
        
        self.stop_button = ttk.Button(self.current_frame, text="Detener Captura", command=self.stop_capture)
        self.stop_button.pack(pady=10)

        # Área de reporte de paquetes
        self.text_area = tk.Text(self.current_frame, height=30, width=100, font=("Courier", 10), bg="#f1f1f1", fg="black")
        self.text_area.pack(pady=10, expand=True)

        # Configura el gráfico en tiempo real
        self.live_plot = LivePlot()
        self.fig_canvas = FigureCanvasTkAgg(self.live_plot.fig, master=self.current_frame)
        self.fig_canvas.get_tk_widget().pack(pady=10)

    def show_graph_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill=tk.BOTH, expand=True)

        # Crear y mostrar el gráfico estático de protocolos
        self.static_graph_button = tk.Button(self.current_frame, text="Mostrar Gráfico de Protocolos", command=self.show_static_graph)
        self.static_graph_button.pack(pady=10)

    def show_ping_frame(self):
        # Crear un nuevo frame para hacer ping
        if self.current_frame:
            self.current_frame.destroy()
        
        self.current_frame = tk.Frame(self.root, bg="black", bd=2, relief="solid")
        self.current_frame.pack(fill=tk.BOTH, expand=True)

        # Titulo para la sección de Ping
        title_label = ttk.Label(self.current_frame, text="Hacer Ping a Servidor", style="TLabel")
        title_label.pack(pady=20)

        # Cuadro de entrada para la dirección del servidor
        self.ping_label = ttk.Label(self.current_frame, text="Dirección IP o Nombre del Servidor", style="TLabel")
        self.ping_label.pack(pady=5)

        self.ping_entry = tk.Entry(self.current_frame, width=50, font=("Arial", 12), bg="black", fg="white", insertbackground="white")
        self.ping_entry.pack(pady=5)

        self.ping_result_label = ttk.Label(self.current_frame, text="Resultado del Ping: ", style="TLabel")
        self.ping_result_label.pack(pady=10)

        self.ping_button = ttk.Button(self.current_frame, text="Hacer Ping", command=self.ping_server)
        self.ping_button.pack(pady=10)

    def ping_server(self):
        # Obtener el servidor desde la entrada
        server = self.ping_entry.get()

        # Realizar el ping usando ping3
        try:
            response = ping(server)
            if response is None:
                result = f"El servidor {server} no respondió al ping."
            else:
                result = f"Ping a {server}: {response:.4f} ms"
        except Exception as e:
            result = f"Error al hacer ping: {e}"

        # Mostrar el resultado en la etiqueta
        self.ping_result_label.config(text=f"Resultado del Ping: {result}")

    def start_capture(self):
        if not self.running:
            self.running = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.start()
            self.update_plot()

    def capture_packets(self):
        # Obtén el valor del filtro
        filter_value = self.filter_entry.get().strip()

        if filter_value:
            self.active_filter_label.config(text=f"Filtro activo: {filter_value}")
            print(f"Iniciando captura con filtro: {filter_value}")
            sniff(prn=self.packet_callback, filter=filter_value, count=50)
        else:
            self.active_filter_label.config(text="Filtro activo: Todos los paquetes")
            print("Iniciando captura de todos los paquetes (sin filtro)")
            # Intenta ejecutar sniff sin filtro
            sniff(prn=self.packet_callback, count=50)  # Captura todos los paquetes

    def packet_callback(self, packet):
        # Analizar el paquete
        report = analyze_packet(packet)
        self.text_area.insert(tk.END, report + "\n")
        self.text_area.see(tk.END)  # Desplaza automáticamente hacia abajo

        # Contar los protocolos
        if packet.haslayer(TCP):
            self.protocol_count["TCP"] += 1
        elif packet.haslayer(UDP):
            self.protocol_count["UDP"] += 1
        elif packet.haslayer(ICMP):
            self.protocol_count["ICMP"] += 1
        else:
            self.protocol_count["Otros"] += 1

    def show_static_graph(self):
        # Crear un gráfico estático de los protocolos capturados
        protocols = list(self.protocol_count.keys())
        counts = list(self.protocol_count.values())

        # Crear el gráfico de barras
        fig, ax = plt.subplots()
        ax.bar(protocols, counts, color=["blue", "green", "red", "orange"])

        ax.set_xlabel('Protocolos')
        ax.set_ylabel('Cantidad de Paquetes')
        ax.set_title('Distribución de Protocolos Capturados')

        # Mostrar el gráfico en la interfaz
        self.static_graph_canvas = FigureCanvasTkAgg(fig, master=self.current_frame)
        self.static_graph_canvas.get_tk_widget().pack(pady=10)
        self.static_graph_canvas.draw()

    def update_plot(self):
        if self.running:
            # Llama a la función update_plot de LivePlot y redibuja el canvas
            self.live_plot.update_plot(len(self.live_plot.x_data))
            self.fig_canvas.draw_idle()  # Redibuja el gráfico en la interfaz de Tkinter
            # Llama a update_plot cada 1000ms para mantener el gráfico en tiempo real
            self.root.after(1000, self.update_plot)

    def stop_capture(self):
        self.running = False
        print("Captura detenida.")

    def show_education_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

    # Crear un nuevo frame educativo
        self.current_frame = tk.Frame(self.root, bg="black", bd=2, relief="solid")
        self.current_frame.pack(fill=tk.BOTH, expand=True)

    # Titulo para la sección educativa
        title_label = ttk.Label(self.current_frame, text="Apartado Educativo", style="TLabel")
        title_label.pack(pady=20)

    # Pestañas para organizar las secciones educativas
        notebook = ttk.Notebook(self.current_frame)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)

    # Sección: Tipos de Paquetes
        packets_frame = tk.Frame(notebook, bg="white")
        packets_text = tk.Text(packets_frame, wrap="word", bg="white", fg="black", font=("Helvetica", 12), relief="flat")
        packets_text.insert("1.0", """
        TIPOS DE PAQUETES:
        - TCP: Protocolo de control de transmisión. Usado para conexiones confiables, como navegadores web y transferencias de archivos.
        - UDP: Protocolo de datagramas de usuario. Rápido pero sin garantía de entrega. Común en streaming y juegos en línea.
        - ICMP: Protocolo de mensajes de control de Internet. Base de herramientas como ping para evaluar conectividad.
        - HTTP: Protocolo de transferencia de hipertexto. Utilizado para cargar páginas web.
        - DNS: Sistema de nombres de dominio. Traduce nombres de dominio (e.g., google.com) a direcciones IP.
    """)
        packets_text.config(state="disabled")
        packets_text.pack(expand=True, fill="both", padx=10, pady=10)
        notebook.add(packets_frame, text="Tipos de Paquetes")

    # Sección: Campos Analizados
        fields_frame = tk.Frame(notebook, bg="white")
        fields_text = tk.Text(fields_frame, wrap="word", bg="white", fg="black", font=("Helvetica", 12), relief="flat")
        fields_text.insert("1.0", """
            CAMPOS ANALIZADOS:
            - Dirección IP de Origen/Destino: Identifica la máquina que envía y recibe el paquete.
            - Puerto de Origen/Destino: Especifica la aplicación o servicio asociado al paquete.
            - TTL: Tiempo de vida del paquete, usado para evitar que los paquetes circulen indefinidamente.
            - Tamaño del Paquete: Indica cuántos bytes contiene el paquete.
        """)
        fields_text.config(state="disabled")
        fields_text.pack(expand=True, fill="both", padx=10, pady=10)
        notebook.add(fields_frame, text="Campos Analizados")

    # Sección: Ping
        ping_frame = tk.Frame(notebook, bg="white")
        ping_text = tk.Text(ping_frame, wrap="word", bg="white", fg="black", font=("Helvetica", 12), relief="flat")
        ping_text.insert("1.0", """
            MEDICIÓN DE PING:
            - El ping mide la latencia (tiempo de ida y vuelta) entre su computadora y un servidor remoto.
            - Ayuda a evaluar la calidad de la conexión y detectar problemas como servidores no accesibles o retrasos.
        """)
        ping_text.config(state="disabled")
        ping_text.pack(expand=True, fill="both", padx=10, pady=10)
        notebook.add(ping_frame, text="Medición de Ping")

        # Botón para regresar al menú principal
        back_button = ttk.Button(self.current_frame, text="Volver al Menú Principal", command=self.show_capture_frame)
        back_button.pack(pady=10)

root = tk.Tk()
app = NetworkAnalyzerApp(root)
root.mainloop()