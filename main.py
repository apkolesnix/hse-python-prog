import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Загрузка данных из файла JSON
with open('events.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Преобразование в DataFrame
df = pd.DataFrame(data["events"])

# Анализ распределения
print("Распределение событий по типам:")
print(df['signature'].value_counts())
print("\nСтатистика:")
print(df['signature'].describe())

# Построение графика
plt.figure(figsize=(12, 6))
sns.countplot(data=df, y="signature",
              order=df['signature'].value_counts().index,
              palette='Blues_r')
plt.title("Распределение типов событий информационной безопасности", fontsize=14, pad=20)
plt.xlabel("Количество событий", fontsize=12)
plt.ylabel("Тип события (signature)", fontsize=12)
plt.tight_layout()
plt.show()
