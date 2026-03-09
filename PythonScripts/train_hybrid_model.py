"""
Скрипт обучения гибридной IDS-модели.

Поскольку CICIDS2017 работает с flow-уровнем (15+ фич на TCP-поток),
а наша система работает с source-уровнем (6 агрегированных фич по IP),
мы генерируем синтетические обучающие данные на основе реалистичных
профилей атак и нормального трафика.

Профили атак взяты из:
  - CICIDS2017 статистики (средние значения по типам атак)
  - RFC 4732 (DoS характеристики)
  - Опыта сетевой безопасности (port scan, brute force паттерны)
"""

import numpy as np
import os
import sys

# Добавляем путь к модулю hybrid_ids
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hybrid_ids import HybridIDS

RANDOM_STATE = 42
rng = np.random.default_rng(RANDOM_STATE)

# Путь для сохранения модели
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'MLModels', 'hybrid_ids_v1.pkl')


# ===========================================================================
# Генерация синтетических данных
# ===========================================================================

def generate_normal_traffic(n: int) -> np.ndarray:
    """
    Нормальный трафик: редкие запросы, мало портов, умеренный размер пакетов.
    Типичный паттерн: рабочая станция, сервер мониторинга SCADA.
    """
    return np.column_stack([
        rng.uniform(0.1, 50, n),        # PacketsPerSecond: 0.1–50 pps
        rng.uniform(200, 1400, n),       # AveragePacketSize: 200–1400 байт
        rng.integers(1, 8, n),           # UniquePorts: 1–7 (мало портов)
        rng.uniform(1e3, 5e6, n),        # TotalBytes: 1 KB – 5 MB
        rng.integers(10, 1000, n),       # PacketCount: 10–1000
        rng.uniform(0.0, 0.25, n),       # DangerScore: низкий
    ]).astype(float)


def generate_dos_attack(n: int) -> np.ndarray:
    """
    DoS/DDoS: очень высокая скорость пакетов, много байт, мало уникальных портов.
    Источник: CICIDS2017 DoS Hulk, DoS Slowloris профили.
    """
    return np.column_stack([
        rng.uniform(500, 5000, n),       # PacketsPerSecond: 500–5000 pps (характерно для DoS)
        rng.uniform(50, 600, n),         # AveragePacketSize: мелкие пакеты (SYN flood)
        rng.integers(1, 4, n),           # UniquePorts: 1–3 (один целевой порт)
        rng.uniform(1e7, 1e9, n),        # TotalBytes: 10 MB – 1 GB
        rng.integers(5000, 500000, n),   # PacketCount: очень много
        rng.uniform(0.6, 1.0, n),        # DangerScore: высокий
    ]).astype(float)


def generate_port_scan(n: int) -> np.ndarray:
    """
    Сканирование портов: умеренная скорость, ОЧЕНЬ много уникальных портов,
    маленькие пакеты (TCP SYN).
    Источник: Nmap/Masscan профили, CICIDS2017 PortScan.
    """
    return np.column_stack([
        rng.uniform(10, 300, n),         # PacketsPerSecond: умеренная (10–300)
        rng.uniform(40, 80, n),          # AveragePacketSize: маленькие (TCP SYN = ~60 байт)
        rng.integers(50, 65535, n),      # UniquePorts: КЛЮЧЕВОЙ признак — сотни/тысячи портов
        rng.uniform(1e4, 5e6, n),        # TotalBytes: умеренно
        rng.integers(100, 50000, n),     # PacketCount: умеренно
        rng.uniform(0.3, 0.8, n),        # DangerScore: средний-высокий
    ]).astype(float)


def generate_brute_force(n: int) -> np.ndarray:
    """
    Brute force (SSH/RDP): постоянная средняя скорость, 1–2 порта,
    характерный размер пакетов аутентификации.
    Источник: CICIDS2017 FTP-Patator, SSH-Patator профили.
    """
    return np.column_stack([
        rng.uniform(5, 100, n),          # PacketsPerSecond: умеренная
        rng.uniform(100, 400, n),        # AveragePacketSize: auth-пакеты
        rng.integers(1, 3, n),           # UniquePorts: 1–2 (22, 3389, 21)
        rng.uniform(5e4, 2e7, n),        # TotalBytes: умеренно
        rng.integers(500, 20000, n),     # PacketCount: много попыток
        rng.uniform(0.4, 0.85, n),       # DangerScore: средний-высокий
    ]).astype(float)


def generate_data_exfiltration(n: int) -> np.ndarray:
    """
    Утечка данных: большой объём исходящих данных, нетипичные порты,
    нечастые но объёмные передачи.
    """
    return np.column_stack([
        rng.uniform(1, 30, n),           # PacketsPerSecond: невысокая (скрытность)
        rng.uniform(1000, 9000, n),      # AveragePacketSize: большие пакеты (данные)
        rng.integers(1, 5, n),           # UniquePorts: мало (1–2 C2 сервера)
        rng.uniform(1e7, 1e10, n),       # TotalBytes: ОЧЕНЬ много (гигабайты)
        rng.integers(1000, 100000, n),   # PacketCount: умеренно
        rng.uniform(0.45, 0.9, n),       # DangerScore: средний-высокий
    ]).astype(float)


# ===========================================================================
# Основная функция
# ===========================================================================

def generate_dataset(
    n_normal: int = 2000,
    n_dos: int = 500,
    n_scan: int = 500,
    n_brute: int = 400,
    n_exfil: int = 300,
):
    """
    Собирает полный датасет из всех профилей трафика.
    Возвращает (X, y) где y: 0=нормальный, 1=атака.
    """
    print("Генерация синтетических обучающих данных...")
    print(f"  Нормальный трафик: {n_normal} образцов")
    print(f"  DoS-атаки:         {n_dos} образцов")
    print(f"  Сканирование:      {n_scan} образцов")
    print(f"  Brute force:       {n_brute} образцов")
    print(f"  Утечка данных:     {n_exfil} образцов")

    X_normal    = generate_normal_traffic(n_normal)
    X_dos       = generate_dos_attack(n_dos)
    X_scan      = generate_port_scan(n_scan)
    X_brute     = generate_brute_force(n_brute)
    X_exfil     = generate_data_exfiltration(n_exfil)

    X = np.vstack([X_normal, X_dos, X_scan, X_brute, X_exfil])
    y = np.hstack([
        np.zeros(n_normal, dtype=int),
        np.ones(n_dos,    dtype=int),
        np.ones(n_scan,   dtype=int),
        np.ones(n_brute,  dtype=int),
        np.ones(n_exfil,  dtype=int),
    ])

    # Перемешиваем
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


def evaluate_model(model: HybridIDS, X_test: np.ndarray, y_test: np.ndarray):
    """Простая оценка качества модели на тестовой выборке."""
    results_json = model.predict_batch(
        __import__('json').dumps([
            {
                'PacketsPerSecond':  float(X_test[i, 0]),
                'AveragePacketSize': float(X_test[i, 1]),
                'UniquePorts':       float(X_test[i, 2]),
                'TotalBytes':        float(X_test[i, 3]),
                'PacketCount':       float(X_test[i, 4]),
                'DangerScore':       float(X_test[i, 5]),
                'SourceIP':          f'test_{i}',
            }
            for i in range(len(X_test))
        ])
    )
    import json
    results = json.loads(results_json)

    y_pred = np.array([1 if r['isAttack'] else 0 for r in results])

    tp = int(np.sum((y_pred == 1) & (y_test == 1)))
    tn = int(np.sum((y_pred == 0) & (y_test == 0)))
    fp = int(np.sum((y_pred == 1) & (y_test == 0)))
    fn = int(np.sum((y_pred == 0) & (y_test == 1)))

    accuracy  = (tp + tn) / len(y_test)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    print("\nРезультаты на тестовой выборке:")
    print(f"  Accuracy:  {accuracy:.3f}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1-score:  {f1:.3f}")
    print(f"  TP={tp}, TN={tn}, FP={fp}, FN={fn}")


def main():
    print("=" * 60)
    print("  Обучение HybridIDS модели")
    print("=" * 60)

    # 1. Генерация данных
    X, y = generate_dataset()
    total = len(X)
    split = int(total * 0.8)

    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    print(f"\nРазбивка: train={len(X_train)}, test={len(X_test)}")

    # 2. Обучение
    print()
    model = HybridIDS()
    model.train(X_train, y_train)

    # 3. Оценка
    evaluate_model(model, X_test, y_test)

    # 4. Сохранение
    print(f"\nСохранение модели в {MODEL_PATH}...")
    model.save(MODEL_PATH)
    print("\nГотово! Модель обучена и сохранена.")
    print(f"Путь: {MODEL_PATH}")


if __name__ == '__main__':
    main()
