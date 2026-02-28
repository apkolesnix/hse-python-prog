import os
import sys
import json
import time
import requests
from requests.auth import HTTPBasicAuth

# Настройки API
API_URL = "https://www.virustotal.com/api/v3/"
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')  # Рекомендуется переменная окружения


def check_api_key():
    """Проверка наличия API-ключа."""
    if not API_KEY:
        print("Ошибка: Установите VIRUSTOTAL_API_KEY в переменных окружения.")
        print("Пример: export VIRUSTOTAL_API_KEY='your_key_here'")
        sys.exit(1)
    print(f"API-ключ установлен: {'*' * (len(API_KEY) - 4)} {API_KEY[-4:]}")


def upload_file(file_path):
    """Загрузка файла на сканирование."""
    with open(file_path, 'rb') as f:
        files = {'file': f}
        headers = {'apikey': API_KEY}
        response = requests.post(API_URL + 'files', files=files, headers=headers)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        print(f"Файл загружен. ID анализа: {analysis_id}")
        return analysis_id
    else:
        print(f"Ошибка загрузки: {response.status_code} - {response.text}")
        sys.exit(1)


def get_scan_status(analysis_id):
    """Получение статуса сканирования."""
    headers = {'x-apikey': API_KEY}
    response = requests.get(API_URL + analysis_id, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Ошибка получения статуса: {response.status_code} - {response.text}")
        sys.exit(1)


def main(file_path):
    """Основная функция."""
    check_api_key()

    # Этап 2: Загрузка файла
    analysis_id = upload_file(file_path)

    # Этап 3: Ожидание и получение результата (max 60 сек)
    print("Ожидание завершения сканирования...")
    for _ in range(12):  # ~60 сек
        time.sleep(5)
        result = get_scan_status(analysis_id)
        status = result['data']['attributes']['status']['status']
        print(f"Статус: {status}")

        if status == 'completed':
            # Вывод JSON в консоль
            print("\n=== JSON-ОТВЕТ ===")
            print(json.dumps(result, indent=2, ensure_ascii=False))

            # Сохранение в файл
            with open('result.json', 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print("\nРезультат сохранен в result.json")
            return
        elif status == 'queued':
            continue
        else:
            print(f"Неожиданный статус: {status}")
            return

    print("Таймаут: сканирование не завершено вовремя.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python script.py <путь_к_файлу>")
        sys.exit(1)
    main(sys.argv[1])
