"""
Скрипт обучения HybridIDS на Flow-CSV формате CICIDS2017.

Положи файл(ы) в одну папку — метки берутся из колонки Label:
  PythonScripts/data/cicids2017/
    Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv   (BENIGN + DDoS)
    Friday-WorkingHours-Afternoon-PortScan.csv          (BENIGN + PortScan)
    Wednesday-workingHours.pcap_ISCX.csv               (BENIGN + DoS)

Не нужны отдельные папки normal/ и attack/ — всё в одной папке data/cicids2017/.
"""

import os, sys, json
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hybrid_ids import HybridIDS, FEATURE_NAMES

DATA_DIR   = os.path.join(os.path.dirname(__file__), 'data', 'cicids2017')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'hybrid_ids_v1.pkl')

# Сколько строк читать из каждого файла (None = все)
NROWS = 300_000


def load_flow_csv(filepath: str) -> pd.DataFrame:
    """
    Загружает flow-CSV CICIDS2017.
    Каждая строка = один TCP-поток.
    Маппим flow-признаки на наши 6 source-level признаков напрямую
    (без агрегации по IP — flow уже агрегирован).
    """
    print(f"  Загружаю {os.path.basename(filepath)}...", end=' ', flush=True)
    df = pd.read_csv(filepath, low_memory=False, nrows=NROWS)
    df.columns = df.columns.str.strip()

    # Ищем нужные колонки (имена чуть отличаются в разных версиях датасета)
    def find_col(*candidates):
        for c in candidates:
            match = next((col for col in df.columns if c.lower() in col.lower()), None)
            if match:
                return match
        return None

    col_pps   = find_col('Flow Packets/s')
    col_size  = find_col('Packet Length Mean', 'Average Packet Size', 'Fwd Packet Length Mean')
    col_port  = find_col('Destination Port', 'Dst Port')
    col_bytes = find_col('Flow Bytes/s')
    col_pkts  = find_col('Total Fwd Packets', 'Total Fwd Packet')
    col_label = find_col('Label')

    if not col_label:
        raise ValueError("Колонка Label не найдена")

    # Числовые преобразования
    for col in [col_pps, col_size, col_port, col_bytes, col_pkts]:
        if col:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df['is_attack'] = df[col_label].astype(str).str.strip().apply(
        lambda x: 0 if x.upper() == 'BENIGN' else 1
    )

    result = pd.DataFrame({
        'PacketsPerSecond':  df[col_pps].abs()   if col_pps   else 0.0,
        'AveragePacketSize': df[col_size]         if col_size  else 0.0,
        'UniquePorts':       df[col_port]         if col_port  else 0.0,
        'TotalBytes':        df[col_bytes].abs()  if col_bytes else 0.0,
        'PacketCount':       df[col_pkts]         if col_pkts  else 0.0,
        'DangerScore':       0.0,
        'label':             df['is_attack'],
    }).fillna(0.0)

    n0 = (result['label'] == 0).sum()
    n1 = (result['label'] == 1).sum()
    print(f"{len(result):,} строк  (BENIGN={n0:,}, attack={n1:,})")
    return result


def balance_dataset(X, y, rng):
    n0, n1 = int(np.sum(y==0)), int(np.sum(y==1))
    if n0 == 0 or n1 == 0:
        print("  ВНИМАНИЕ: один класс пустой")
        return X, y
    n_min = min(n0, n1)
    print(f"Балансировка: BENIGN {n0}→{n_min}, attack {n1}→{n_min}")
    idx = rng.permutation(np.concatenate([
        rng.choice(np.where(y==0)[0], n_min, replace=False),
        rng.choice(np.where(y==1)[0], n_min, replace=False),
    ]))
    return X[idx], y[idx]


def evaluate(model, X_test, y_test):
    # Напрямую через sklearn — без predict_batch чтобы избежать
    # зависания joblib ThreadPool на Python 3.14
    X_scaled = model.scaler.transform(X_test)
    y_pred   = model.supervised.predict(X_scaled)

    tp = int(np.sum((y_pred==1) & (y_test==1)))
    tn = int(np.sum((y_pred==0) & (y_test==0)))
    fp = int(np.sum((y_pred==1) & (y_test==0)))
    fn = int(np.sum((y_pred==0) & (y_test==1)))

    acc  = (tp+tn)/len(y_test)
    prec = tp/(tp+fp) if (tp+fp)>0 else 0.0
    rec  = tp/(tp+fn) if (tp+fn)>0 else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0

    print("\n" + "="*50)
    print("  Метрики качества")
    print("="*50)
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1-score:  {f1:.4f}")
    print(f"  TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    print("="*50)


def main():
    rng = np.random.default_rng(42)

    print("="*60)
    print("  Обучение HybridIDS на CICIDS2017 Flow-CSV")
    print("="*60)
    print(f"  Папка данных: {DATA_DIR}")
    print(f"  Строк из каждого файла: {NROWS:,}")

    csv_files = [f for f in os.listdir(DATA_DIR)
                 if f.endswith('.csv') and os.path.isfile(os.path.join(DATA_DIR, f))]

    if not csv_files:
        print(f"\nНет CSV в {DATA_DIR}")
        print("Положите flow-CSV файлы CICIDS2017 прямо в эту папку.")
        return

    print(f"\n[1/4] Загрузка {len(csv_files)} файлов...")
    frames = []
    for fname in sorted(csv_files):
        try:
            df = load_flow_csv(os.path.join(DATA_DIR, fname))
            frames.append(df)
        except Exception as e:
            print(f"  ПРОПУЩЕН {fname}: {e}")

    if not frames:
        print("Не удалось загрузить ни одного файла.")
        return

    df_all = pd.concat(frames, ignore_index=True)

    print(f"\n[2/4] Итого: {len(df_all):,} записей")
    print(f"  BENIGN:  {(df_all['label']==0).sum():,}")
    print(f"  Атак:    {(df_all['label']==1).sum():,}")

    print("\n  Статистика признаков:")
    for feat in FEATURE_NAMES[:4]:
        n = df_all[df_all['label']==0][feat].mean()
        a = df_all[df_all['label']==1][feat].mean()
        r = a/n if n > 0 else float('inf')
        print(f"    {feat:20s}: BENIGN={n:10.2f}, attack={a:10.2f}  ratio={r:.1f}x")

    print(f"\n[3/4] Обучение...")
    X = df_all[FEATURE_NAMES].values.astype(float)
    y = df_all['label'].values.astype(int)
    X, y = balance_dataset(X, y, rng)

    split = int(len(X) * 0.8)
    model = HybridIDS()
    model.train(X[:split], y[:split])

    print(f"\n[4/4] Оценка и сохранение...")
    evaluate(model, X[split:], y[split:])
    model.save(MODEL_PATH)
    print(f"\nГотово! {MODEL_PATH}")


if __name__ == '__main__':
    main()
