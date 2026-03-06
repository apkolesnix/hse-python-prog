import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import requests
from datetime import datetime
from collections import Counter

# Этап 1: Сбор данных (имитация логов Suricata + уязвимости)
suricata_logs = [
    {'timestamp': '2026-03-01T10:00:00', 'event_type': 'alert', 'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8',
     'signature': 'ET SCAN Suspicious DNS Query', 'action': 'allowed'},
    {'timestamp': '2026-03-01T10:01:00', 'event_type': 'alert', 'src_ip': '192.168.1.101', 'dst_ip': '1.1.1.1',
     'signature': 'GPL ATTACK_RESPONSE id check returned root', 'action': 'allowed'},
    {'timestamp': '2026-03-01T10:02:00', 'event_type': 'alert', 'src_ip': '192.168.1.100', 'dst_ip': '8.8.4.4',
     'signature': 'ET SCAN Potential SSH Brute Force', 'action': 'allowed'},
    {'timestamp': '2026-03-01T10:03:00', 'event_type': 'alert', 'src_ip': '192.168.1.102', 'dst_ip': '9.9.9.9',
     'signature': 'ET POLICY Suspicious Domain', 'action': 'allowed'},
    {'timestamp': '2026-03-01T10:04:00', 'event_type': 'alert', 'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8',
     'signature': 'ET SCAN Nmap Scan', 'action': 'allowed'},
    {'timestamp': '2026-03-01T10:05:00', 'event_type': 'alert', 'src_ip': '192.168.1.103', 'dst_ip': '1.1.1.1',
     'signature': 'Benign traffic', 'action': 'allowed'},
]

vulns_data = [
    {'id': 'CVE-2025-1234', 'cvss_score': 9.8, 'software': 'OpenSSL', 'description': 'Critical RCE'},
    {'id': 'CVE-2025-5678', 'cvss_score': 7.5, 'software': 'Apache', 'description': 'High XSS'},
    {'id': 'CVE-2025-9012', 'cvss_score': 4.3, 'software': 'Linux Kernel', 'description': 'Medium DoS'},
    {'id': 'CVE-2025-3456', 'cvss_score': 9.1, 'software': 'Docker', 'description': 'Critical Esc'},
]

VT_API_KEY = '7447d962a4586a77cf9c63c2960878c2a45409596771a65485a1423b01eb3482'
ips_to_check = ['8.8.8.8', '1.1.1.1']
for ip in ips_to_check:
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    resp = requests.get(url, headers={'x-apikey': VT_API_KEY})
    if resp.status_code == 200:
        data = resp.json()['data']['attributes']
        if data['last_analysis_stats']['malicious'] > 0:
            suricata_logs.append({'src_ip': ip, 'threat': 'VT Malicious'})

# VULNERS_URL = 'https://vulners.com/api/v3/search/lucene/'
# query = '{"query": "cvss.score:>7", "size": 10}'
# resp = requests.post(VULNERS_URL, json=json.loads(query))
# vulns_data.extend(resp.json().get('data', {}).get('search', []))

# Этап 2: Анализ с pandas
df_logs = pd.DataFrame(suricata_logs)
df_vulns = pd.DataFrame(vulns_data)

# Подозрительные IP (топ по алертам)
susp_ips_count = df_logs['src_ip'].value_counts()
suspicious_ips = susp_ips_count[susp_ips_count > 1].index.tolist()

# Высокие уязвимости (CVSS >=7 - high/critical)[web:15]
high_vulns = df_vulns[df_vulns['cvss_score'] >= 7.0]

threats = []
for ip in suspicious_ips:
    threats.append({'ip': ip, 'threat_type': 'Suspicious Traffic (multiple alerts)', 'severity': 'High'})
for _, vuln in high_vulns.iterrows():
    threats.append(
        {'vuln_id': vuln['id'], 'cvss': vuln['cvss_score'], 'threat_type': 'High CVSS', 'severity': 'Critical'})

# Этап 3: Реагирование
for threat in threats:
    print(f"🚨 УГРОЗА: {threat}")
    print("🔒 Имитация: Блокировка IP в firewall + уведомление в Telegram/email")
    print("---")

# Этап 4: Отчёты и графики
report = {
    'date': datetime.now().isoformat(),
    'threats_count': len(threats),
    'susp_ips': suspicious_ips,
    'high_vulns': high_vulns.to_dict('records'),
    'top_ips': susp_ips_count.head().to_dict()
}
with open('threat_report.json', 'w', encoding='utf-8') as f:
    json.dump(report, f, ensure_ascii=False, indent=4)

df_logs.to_csv('suricata_logs.csv', index=False)

# График 1: Топ-5 IP
plt.figure(figsize=(10, 6))
susp_ips_count.head().plot(kind='bar', color='red')
plt.title('Топ-5 подозрительных IP по алертам')
plt.xlabel('IP-адрес')
plt.ylabel('Количество событий')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('top_ips.png', dpi=300, bbox_inches='tight')
plt.close()

# График 2: Распределение CVSS
plt.figure(figsize=(8, 5))
sns.histplot(df_vulns['cvss_score'], bins=10, kde=True, color='orange')
plt.title('Распределение CVSS-баллов')
plt.xlabel('CVSS Score')
plt.ylabel('Количество')
plt.savefig('cvss_dist.png', dpi=300, bbox_inches='tight')
plt.close()

print("✅ Готово! Файлы: threat_report.json, suricata_logs.csv, top_ips.png, cvss_dist.png")
