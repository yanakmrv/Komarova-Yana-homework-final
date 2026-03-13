#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Автоматизированный мониторинг и реагирование на угрозы
--------------------------------------------------------
Источники данных:
1. Логи Suricata (файл suricata_logs.json)
2. API VirusTotal (проверка IP-адресов)

Анализ:
1. Извлекаются все внешние IP-адреса источников (src_ip)
2. Для каждого IP выполняется запрос к VirusTotal
3. Подозрительными считаются IP с количеством вредоносных детектов > 0

Реагирование:
1. Вывод сообщения о найденных угрозах
2. Имитация блокировки IP (печать в консоль)

Отчёт:
1. CSV-файл с результатами проверки (threat_report.csv)
2. График распределения вредоносных детектов (threat_graph.png)
"""

import requests
import pandas as pd
import matplotlib.pyplot as plt
import json
import time
import os
from datetime import datetime

API_KEY = "c7877b786e87433311b5948fd6ca33848ace0dafb3742b0bfb498b19793b18aa"
LOG_FILE = "suricata_logs.jsonl"
REPORT_CSV = "threat_report.csv"
GRAPH_PNG = "threat_graph.png"
REQUEST_DELAY = 15

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def load_logs(file_path):
    """
    загружаем логи из json-файла
    воззвращаем список всех исходных ip-адресов
    """
    ips = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    src_ip = event.get('src_ip')
                    if src_ip:
                        ips.add(src_ip)
                except json.JSONDecodeError:
                    print(f"Предупреждение: не удалось распарсить строку: {line}")
    except FileNotFoundError:
        print(f"Ошибка: файл {file_path} не найден.")
        return []
    return list(ips)

def query_virustotal(ip):
    """
    отправляем запрос к virustotal для указанного ip
    возвращаем словарь с результатами или none при ошибке
    """
    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }
    try:
        response = requests.get(VT_URL + ip, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            country = attributes.get('country', 'Unknown')
            result = {
                'ip': ip,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'country': country,
                'timestamp': datetime.now().isoformat()
            }
            return result
        elif response.status_code == 404:
            # IP отсутствует в базе VirusTotal
            print(f"IP {ip} не найден в VirusTotal.")
            return None
        else:
            print(f"Ошибка {response.status_code} для IP {ip}: {response.text}")
            return None
    except Exception as e:
        print(f"Исключение при запросе IP {ip}: {e}")
        return None

def main():
    print("=== Запуск мониторинга угроз ===\n")

    # загрузка логов
    print("[1] Загрузка логов Suricata...")
    ips = load_logs(LOG_FILE)
    if not ips:
        print("Нет IP для анализа. Завершение.")
        return
    print(f"Найдено уникальных исходных IP: {len(ips)}")
    print("IP:", ips, "\n")

    # поверка IP через VirusTotal
    print("[2] Запрос к VirusTotal (с задержкой {} сек)...".format(REQUEST_DELAY))
    results = []
    for i, ip in enumerate(ips, 1):
        print(f"  {i}/{len(ips)}: проверяем {ip}...")
        data = query_virustotal(ip)
        if data:
            results.append(data)
        # задержка, чтобы не превысить лимиты бесплатного API
        if i < len(ips):
            time.sleep(REQUEST_DELAY)

    if not results:
        print("Нет данных от VirusTotal. Завершение.")
        return

    # анализ результатов
    print("\n[3] Анализ угроз...")
    df = pd.DataFrame(results)
    # сортируем по убыванию malicious
    df = df.sort_values('malicious', ascending=False)

    # выявляем подозрительные IP
    threats = df[df['malicious'] > 0]
    if not threats.empty:
        print("Обнаружены потенциальные угрозы:")
        for _, row in threats.iterrows():
            print(f"  IP {row['ip']} | вредоносных детектов: {row['malicious']} | страна: {row['country']}")
            # имитация блокировки
            print(f"  >>> Имитация блокировки IP {row['ip']} (правило firewall)\n")
    else:
        print("Подозрительных IP не обнаружено.\n")

    # сохранение отчёта
    print("[4] Сохранение отчёта в CSV...")
    df.to_csv(REPORT_CSV, index=False, encoding='utf-8')
    print(f"Отчёт сохранён: {REPORT_CSV}")

    # построение графика
    print("[5] Построение графика...")
    plt.figure(figsize=(10, 6))
    # берём топ-10 IP по количеству вредоносных детектов
    plot_df = df.head(10)
    plt.barh(plot_df['ip'], plot_df['malicious'], color='coral')
    plt.xlabel('Количество вредоносных детектов')
    plt.title('Топ IP по обнаружениям в VirusTotal')
    plt.gca().invert_yaxis()  # чтобы самый опасный был сверху
    plt.tight_layout()
    plt.savefig(GRAPH_PNG, dpi=100)
    print(f"График сохранён: {GRAPH_PNG}")

    print("\n=== Работа скрипта завершена ===")

if __name__ == "__main__":
    main()