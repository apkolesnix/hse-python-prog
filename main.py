import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def extract_results(d, path='', df_list=None):
    """Рекурсивно извлекает числовые значения из вложенного словаря."""
    if df_list is None:
        df_list = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_path = f"{path}.{k}" if path else k
            if isinstance(v, (int, float)):
                df_list.append({'key': new_path, 'value': v})
            else:
                extract_results(v, new_path, df_list)
    elif isinstance(d, list):
        for i, item in enumerate(d):
            extract_results(item, f"{path}[{i}]", df_list)
    return df_list

# Пример дампа (замените на свой)
dump_str = '''
{
    "results": {
        "test1": {"metric1": 10, "metric2": 20, "category": "A"},
        "test2": {"metric1": 15, "metric2": 25, "category": "B"},
        "test3": {"metric1": 12, "metric2": 18, "category": "A"}
    }
}
'''

# Парсинг и извлечение
data = json.loads(dump_str)
flat_data = extract_results(data)
df = pd.DataFrame(flat_data)

print("Извлеченные ключевые результаты:")
print(df)

# Визуализация
plt.figure(figsize=(10, 6))
sns.barplot(data=df, x='key', y='value')
plt.title('Ключевые метрики из дампа')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('metrics.png')
plt.show()
