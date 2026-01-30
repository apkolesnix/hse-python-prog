import sys
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Raw
import random


def process_packet(packet):
    try:
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            print("\n=== HTTP ЗАПРОС ===")
            print(f"От: {ip_src}:{packet[TCP].sport}")
            print(f"На: {ip_dst}:{packet[TCP].dport}")
            print(f"Метод: {req.Method.decode(errors='ignore')}")
            print(f"Host: {req.Host.decode(errors='ignore')}")
            print(f"Path: {req.Path.decode(errors='ignore')}")

            # Безопасный доступ к User-Agent через fields_desc
            ua = None
            for field in req.fields_desc:
                if field.name == "User_Agent":
                    ua = req.getfieldval(field.name)
                    break
            if ua:
                print(f"User-Agent: {ua.decode(errors='ignore')}")

            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    print(f"Raw данные: {raw_data[:200].decode('utf-8', errors='ignore')}...")
                except:
                    print(f"Raw данные: {raw_data[:50]}...")

        elif packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            print("\n=== HTTP ОТВЕТ ===")
            print(f"От: {ip_src}:{packet[TCP].sport}")
            print(f"На: {ip_dst}:{packet[TCP].dport}")

            status_code = resp.getfieldval("Status_Code")
            if status_code:
                print(f"Код ответа: {status_code}")

            reason = resp.getfieldval("Reason")
            if reason:
                print(f"Reason: {reason.decode(errors='ignore')}")

            if packet.haslayer(Raw):
                print(f"Тело ответа: {len(packet[Raw].load)} байт")

    except Exception as e:
        # Игнорируем ошибки обработки отдельных пакетов
        pass


# интерфейс можно передать первым аргументом
iface = sys.argv[1] if len(sys.argv) > 1 else None

print(f"Непрерывный перехват HTTP-трафика на интерфейсе '{iface}' (Ctrl+C для выхода)")

try:
    sniff(
        filter="tcp port 80 or tcp port 443",
        prn=process_packet,
        iface=iface,
        store=False  # не сохраняем пакеты в память
    )
except KeyboardInterrupt:
    print("\nПерехват остановлен пользователем")
except Exception as e:
    print(f"Ошибка: {e}")
