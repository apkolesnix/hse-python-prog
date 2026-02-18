import pandas as pd
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Этап 1: Загрузка и нормализация данных
with open('botsv1.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

df = pd.json_normalize(data)
print(f"Загружено {len(df)} записей. Колонки: {len(df.columns)}")

# Этап 2: Анализ WinEventLog:Security
winevent_df = df[df['result.sourcetype'] == 'WinEventLog:Security'].copy()
winevent_df['EventCode'] = pd.to_numeric(winevent_df['result.EventCode'], errors='coerce')

# Подозрительные EventID (ошибки входа, эскалация, процессы)
suspicious_ids = [4625, 4648, 4672, 4673, 4703, 4688, 5145, 4656, 4689, 5140]
winevent_susp = winevent_df[winevent_df['EventCode'].isin(suspicious_ids)]

print(f"WinEventLog: {len(winevent_df)}, подозрительных: {len(winevent_susp)}")
print("Топ подозрительных EventCode:", winevent_susp['EventCode'].value_counts().head().to_dict())

# Этап 3: Анализ DNS-логов (подозрительные домены: редкие, C2)
dns_mask = df['result.sourcetype'].str.contains('DNS', na=False, case=False) | \
           (df['result.LogName'] == 'DNS')
dns_df = df[dns_mask].copy()
if len(dns_df) > 0:
    suspicious_dns = dns_df['result.QueryName'].value_counts()
    print("Топ DNS-запросов (подозрительные):", suspicious_dns.to_dict())
else:
    print("DNS-логи не найдены отдельно")

# Этап 4: Визуализация топ-10 подозрительных событий (WinEventLog)
top10 = winevent_susp['EventCode'].value_counts().head(10)
plt.figure(figsize=(12, 6))
sns.barplot(x=top10.index.astype(str), y=top10.values, palette='Reds_r')
plt.title('Топ-10 наиболее распространённых подозрительных событий (WinEventLog:Security)')
plt.xlabel('EventCode')
plt.ylabel('Количество')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('top_suspicious_events.png', dpi=300, bbox_inches='tight')
plt.show()

print("График сохранён как 'top_suspicious_events.png'")
