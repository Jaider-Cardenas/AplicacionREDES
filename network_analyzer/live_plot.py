#live_plot.py
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

class LivePlot:
    def __init__(self):
        # Elimina la referencia a canvas
        self.fig, self.ax = plt.subplots()
        self.x_data, self.y_data = [], []
        self.packet_count = 0

        self.ax.set_xlabel('Tiempo (segundos)')
        self.ax.set_ylabel('Paquetes capturados')
        self.ax.set_title('Paquetes capturados en tiempo real')

    def update_plot(self, frame):
        self.packet_count += 1
        self.x_data.append(frame)
        self.y_data.append(self.packet_count)
        self.ax.clear()
        self.ax.plot(self.x_data, self.y_data, label="Paquetes capturados")
        self.ax.legend(loc="upper left")

        