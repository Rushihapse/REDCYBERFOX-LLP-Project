import socket
import threading
from queue import Queue
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QPushButton,
    QProgressBar,
    QWidget,
)
from PyQt5.QtGui import QPixmap, QImage, QFont
from PyQt5.QtCore import Qt
import urllib.request

NUM_THREADS = 100
queue = Queue()

# Port scanning logic
def scan_port(ip, port, result_box, progress_bar, total_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
                result_box.append(f"Open Port: {port}, Service: {service}")
            except:
                result_box.append(f"Open Port: {port}, Service: Unknown")
        sock.close()
    except socket.error:
        pass
    finally:
        progress_bar.setValue(progress_bar.value() + 1)

def worker(ip, result_box, progress_bar, total_ports):
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port, result_box, progress_bar, total_ports)
        queue.task_done()

def scan_ip(ip, start_port, end_port, result_box, progress_bar):
    result_box.append(f"Scanning IP Using Redcyberfox Port Scanner: {ip}")
    total_ports = end_port - start_port + 1
    progress_bar.setMaximum(total_ports)
    
    for port in range(start_port, end_port + 1):
        queue.put(port)

    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=worker, args=(ip, result_box, progress_bar, total_ports))
        thread.start()

    queue.join()

def scan_network(start_ip, end_ip, start_port, end_port, result_box, progress_bar):
    start_ip_list = list(map(int, start_ip.split('.')))
    end_ip_list = list(map(int, end_ip.split('.')))

    for i in range(start_ip_list[3], end_ip_list[3] + 1):
        ip = f"{start_ip_list[0]}.{start_ip_list[1]}.{start_ip_list[2]}.{i}"
        scan_ip(ip, start_port, end_port, result_box, progress_bar)

# PyQt5 GUI Application
class CybersecurityScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Redcyberfox Port Scanner")
        self.setGeometry(100, 100, 800, 600)
        
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout(self.main_widget)
        
        self.create_header()
        self.create_input_fields()
        self.create_results_area()
        self.create_progress_bar()

    def create_header(self):
        # Header with a web image and title
        header_layout = QVBoxLayout()

        # Load the image from a web URL
        image_url = "https://lh3.googleusercontent.com/_9n17E1SfSM_YOOewZMQ-cDZid4OQ_4KFEAX3OpKqIc86zwIrA09KWg_3a7UV6kOGZ_K_CEO-OHDDQA6SEZ45fs=w16383"  # Replace with your web image URL
        data = urllib.request.urlopen(image_url).read()
        image = QImage()
        image.loadFromData(data)

        header_image = QLabel()
        pixmap = QPixmap.fromImage(image)
        header_image.setPixmap(pixmap.scaled(780, 180, Qt.KeepAspectRatio))
        header_image.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(header_image)

        header_title = QLabel("Welcome to Redcyberfox Port Scanner")
        header_title.setFont(QFont("Arial", 16, QFont.Bold))
        header_title.setAlignment(Qt.AlignCenter)
        header_title.setStyleSheet("color: red;")
        header_layout.addWidget(header_title)

        self.layout.addLayout(header_layout)

    def create_input_fields(self):
        # Input fields for IP and ports
        input_layout = QHBoxLayout()
        
        self.start_ip_label = QLabel("Start IP:")
        self.start_ip_label.setFont(QFont("Arial", 12))
        self.start_ip_entry = QLineEdit()
        input_layout.addWidget(self.start_ip_label)
        input_layout.addWidget(self.start_ip_entry)

        self.end_ip_label = QLabel("End IP:")
        self.end_ip_label.setFont(QFont("Arial", 12))
        self.end_ip_entry = QLineEdit()
        input_layout.addWidget(self.end_ip_label)
        input_layout.addWidget(self.end_ip_entry)

        self.start_port_label = QLabel("Start Port:")
        self.start_port_label.setFont(QFont("Arial", 12))
        self.start_port_entry = QLineEdit()
        input_layout.addWidget(self.start_port_label)
        input_layout.addWidget(self.start_port_entry)

        self.end_port_label = QLabel("End Port:")
        self.end_port_label.setFont(QFont("Arial", 12))
        self.end_port_entry = QLineEdit()
        input_layout.addWidget(self.end_port_label)
        input_layout.addWidget(self.end_port_entry)

        self.layout.addLayout(input_layout)

        self.start_button = QPushButton("Start Scan")
        self.start_button.setStyleSheet("background-color: red; color: white;")
        self.start_button.clicked.connect(self.start_scan)
        self.layout.addWidget(self.start_button, alignment=Qt.AlignCenter)

    def create_results_area(self):
        # Results display
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setStyleSheet("background-color: #000; color: green; font-family: monospace;")
        self.layout.addWidget(self.result_box)

    def create_progress_bar(self):
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        self.layout.addWidget(self.progress_bar)

    def start_scan(self):
        start_ip = self.start_ip_entry.text()
        end_ip = self.end_ip_entry.text()
        try:
            start_port = int(self.start_port_entry.text())
            end_port = int(self.end_port_entry.text())
        except ValueError:
            self.result_box.append("Ports must be integers!")
            return

        self.result_box.clear()
        threading.Thread(
            target=scan_network,
            args=(start_ip, end_ip, start_port, end_port, self.result_box, self.progress_bar),
        ).start()

# Main function
def main():
    app = QApplication([])
    window = CybersecurityScanner()
    window.show()
    app.exec()

if __name__ == "__main__":
    main()
