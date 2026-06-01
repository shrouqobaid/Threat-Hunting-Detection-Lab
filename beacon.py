import time
import socket

target_ip = "8.8.8.8"
target_port = 80 # الاتصال بمنفذ ويب

print("Starting TCP beaconing simulation...")
while True:
    try:
        # محاولة فتح اتصال TCP حقيقي
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, target_port))
        s.close()
    except:
        pass
    time.sleep(5) # الانتظار 5 ثوانٍ
