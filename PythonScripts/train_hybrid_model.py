"""
PythonScripts/train_hybrid_model.py  (v4)

Pipeline:
  1. Загрузить CSV из data/cicids2017/ + очистка
  2. Силуэт на стратифицированной подвыборке 50k -> топ-15
  3. Пробный RF на всех признаках (подвыборка 100k) -> топ-15 по importance
  4. ФИНАЛЬНЫЙ набор = пересечение. Если < 8 -> добираем из силуэта до 10.
  5. Обучение RF + IF на ПОЛНОЙ выборке с финальным набором
  6. Сохранение .pkl + global_features.json (с разбивкой по блокам A/B/C)

Запуск:
    cd PythonScripts
    python train_hybrid_model.py
    python train_hybrid_model.py --top_k 10 --sample_fs 50000 --sample_rf 100000



Pipeline с поддержкой двух моделей: Random Forest или CatBoost.

Пример:
    python train_hybrid_model.py                              # RF (default)
    python train_hybrid_model.py --model_type catboost        # CatBoost
    python train_hybrid_model.py --model_type rf --fs_method rank_avg

Feature selection остаётся общим (силуэт + RF importance + пересечение),
обучение расходится по типу модели в конце.
"""

import os
import sys
import glob
import argparse
import json
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score, f1_score, roc_auc_score)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cicids_mapping import normalize_cicids_columns
from feature_selection import rank_features, NUMERIC_FEATURES


DEFAULT_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'data', 'cicids2017')


def model_path_for(model_type: str) -> str:
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if model_type == 'catboost':
        return os.path.join(scripts_dir, 'models', 'catboost_ids_v2.pkl')
    return os.path.join(scripts_dir, 'models', 'hybrid_ids_v2.pkl')


def meta_path_for(model_type: str) -> str:
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if model_type == 'catboost':
        return os.path.join(scripts_dir, 'models', 'catboost_features.json')
    return os.path.join(scripts_dir, 'models', 'global_features.json')


# =============================================================
# FEATURE BLOCKS (для меры сходства)
# =============================================================
FEATURE_BLOCKS = {
    'FwdPSHFlags': 'C', 'BwdPSHFlags': 'C',
    'FwdURGFlags': 'C', 'BwdURGFlags': 'C',
    'FINFlagCount': 'C', 'SYNFlagCount': 'C', 'RSTFlagCount': 'C',
    'PSHFlagCount': 'C', 'ACKFlagCount': 'C', 'URGFlagCount': 'C',
    'CWEFlagCount': 'C', 'ECEFlagCount': 'C',
}

def assign_block(name: str) -> str:
    return FEATURE_BLOCKS.get(name, 'B')

def split_features_by_block(features: list) -> dict:
    result = {'A': [], 'B': [], 'C': []}
    for f in features:
        result[assign_block(f)].append(f)
    return result


# =============================================================
# LOAD + CLEAN
# =============================================================
def load_cicids(data_dir: str) -> pd.DataFrame:
    csv_paths = sorted(glob.glob(os.path.join(data_dir, '*.csv')))
    if not csv_paths:
        raise FileNotFoundError(f"Не найдены CSV в {data_dir}")
    print(f"[load] Нашёл {len(csv_paths)} CSV:")
    for p in csv_paths:
        print(f"   - {os.path.basename(p)}")
    dfs = []
    for path in csv_paths:
        print(f"[load] Читаю: {os.path.basename(path)}")
        try:
            df = pd.read_csv(path, low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(path, low_memory=False, encoding='latin-1')
        df = normalize_cicids_columns(df)
        dfs.append(df)
    full = pd.concat(dfs, ignore_index=True)
    print(f"[load] Итого строк: {len(full):,}")
    return full


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    print(f"[clean] Исходно: {len(df):,} строк")
    if 'Label' not in df.columns:
        raise ValueError("Нет столбца Label после нормализации")
    df['Label'] = df['Label'].astype(str).str.strip()
    print(f"[clean] Распределение меток:\n{df['Label'].value_counts()}")
    df['Label'] = df['Label'].apply(lambda x: 0 if x.upper() == 'BENIGN' else 1)
    print(f"[clean] Бинаризовано: {df['Label'].value_counts().to_dict()}")
    numeric_cols = [c for c in NUMERIC_FEATURES if c in df.columns]
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(0.0)
    for c in numeric_cols:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
    df = df.dropna(subset=['Label'])
    print(f"[clean] После очистки: {len(df):,} строк")
    return df


# =============================================================
# FEATURE SELECTION
# =============================================================
def fs_silhouette(df, sample_size, top_n):
    print(f"\n[FS-silhouette] Подвыборка {sample_size:,}, top-{top_n}")
    if len(df) > sample_size:
        df_s, _ = train_test_split(df, train_size=sample_size,
                                   stratify=df['Label'], random_state=42)
    else:
        df_s = df
    numeric = [c for c in NUMERIC_FEATURES if c in df_s.columns]
    records = df_s[numeric].to_dict(orient='records')
    result = json.loads(rank_features(json.dumps(records), top_k=top_n))
    if 'error' in result:
        raise RuntimeError(f"FS failed: {result['error']}")
    top = result['top10']
    print(f"\n[FS-silhouette] Топ-{top_n}:")
    for i, name in enumerate(top, 1):
        r = next(r for r in result['ranking'] if r['feature'] == name)
        bal = r['clusterBalance']
        bal_str = f"{bal:.2%}" if bal is not None else "N/A"
        print(f"   {i:2d}. {name:30s}  sil={r['silhouette']:.4f}  bal={bal_str}")
    return top, result['ranking']


def fs_rf_importance(df, sample_size, top_n):
    print(f"\n[FS-RF] Пробный RF на {sample_size:,} строках")
    if len(df) > sample_size:
        df_s, _ = train_test_split(df, train_size=sample_size,
                                   stratify=df['Label'], random_state=42)
    else:
        df_s = df
    numeric = [c for c in NUMERIC_FEATURES if c in df_s.columns]
    X = df_s[numeric].values.astype(float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    y = df_s['Label'].values.astype(int)
    probe = RandomForestClassifier(
        n_estimators=50, max_depth=15, min_samples_split=10,
        class_weight='balanced', random_state=42, n_jobs=-1)
    probe.fit(X, y)
    imps = list(zip(numeric, probe.feature_importances_))
    imps.sort(key=lambda x: -x[1])
    top = [n for n, _ in imps[:top_n]]
    print(f"\n[FS-RF] Топ-{top_n}:")
    for i, (n, v) in enumerate(imps[:top_n], 1):
        print(f"   {i:2d}. {n:30s}  imp={v:.4f}")
    return top, imps


def method_intersection(sil_top, rf_top, target):
    inter = [f for f in sil_top if f in set(rf_top)]
    print(f"\n[method=intersection] Пересечение ({len(inter)}): {inter}")
    if len(inter) >= target:
        final = inter[:target]
    elif len(inter) >= 8:
        final = inter
    else:
        final = list(inter)
        for f in sil_top:
            if len(final) >= target:
                break
            if f not in final:
                final.append(f)
        print(f"[method=intersection] Добрали из силуэта до {len(final)}")
    return final


def method_rank_avg(sil_top, rf_top, target):
    sil_rank = {f: i + 1 for i, f in enumerate(sil_top)}
    rf_rank = {f: i + 1 for i, f in enumerate(rf_top)}
    penalty_sil = len(sil_top) + 1
    penalty_rf = len(rf_top) + 1
    candidates = set(sil_top) | set(rf_top)
    scores = []
    for f in candidates:
        s = sil_rank.get(f, penalty_sil)
        r = rf_rank.get(f, penalty_rf)
        scores.append((f, (s + r) / 2, s, r))
    scores.sort(key=lambda x: x[1])
    print(f"\n[method=rank_avg] Топ признаков по среднему рангу:")
    for name, avg, s, r in scores[:target]:
        print(f"   {name:30s}  sil={s:2d}, rf={r:2d}, avg={avg:.1f}")
    return [f for f, _, _, _ in scores[:target]]


def method_silhouette_only(sil_top, target):
    return sil_top[:target]


# =============================================================
# TRAIN: DISPATCH ПО ТИПУ МОДЕЛИ
# =============================================================
def train_final(df, features, model_type):
    print(f"\n[train] Обучение {model_type.upper()} на {len(df):,} строках, "
          f"{len(features)} признаках")
    print(f"[train] Признаки: {features}")

    X = df[features].values.astype(float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    y = df['Label'].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"[train] Train: {X_train.shape}, Test: {X_test.shape}")

    # Импортируем нужный класс только когда надо
    if model_type == 'catboost':
        from catboost_ids import CatBoostIDS
        model = CatBoostIDS()
    else:
        from hybrid_ids import HybridIDS
        model = HybridIDS()

    model.train(X_train, y_train, feature_names=features)

    # Оценка
    X_test_scaled = model.scaler.transform(X_test)
    if model_type == 'catboost':
        y_pred = model.supervised.predict(X_test_scaled).flatten().astype(int)
    else:
        y_pred = model.supervised.predict(X_test_scaled)
    y_proba = model.supervised.predict_proba(X_test_scaled)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    try:
        roc = roc_auc_score(y_test, y_proba)
    except Exception:
        roc = float('nan')

    print(f"\n[eval] Accuracy: {acc:.4f}")
    print(f"[eval] F1:       {f1:.4f}")
    print(f"[eval] ROC-AUC:  {roc:.4f}")
    print(f"\n[eval] Classification report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    print(f"[eval] Confusion matrix:\n{confusion_matrix(y_test, y_pred)}")

    return model, {
        'accuracy': float(acc),
        'f1': float(f1),
        'roc_auc': float(roc) if not np.isnan(roc) else None,
        'test_size': int(len(y_test)),
        'model_type': model_type,
    }


# =============================================================
# MAIN
# =============================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data_dir', default=DEFAULT_DATA_DIR)
    parser.add_argument('--model_type', choices=['rf', 'catboost'], default='rf',
                        help='Тип модели: rf (RandomForest) или catboost')
    parser.add_argument('--model_path', default=None,
                        help='Путь к .pkl (по умолчанию — по типу модели)')
    parser.add_argument('--sample_fs', type=int, default=50_000)
    parser.add_argument('--sample_rf', type=int, default=100_000)
    parser.add_argument('--top_k', type=int, default=10)
    parser.add_argument('--top_prefilter', type=int, default=15)
    parser.add_argument('--fs_method',
                        choices=['intersection', 'rank_avg', 'silhouette_only'],
                        default='intersection')
    args = parser.parse_args()

    # Авто-определение путей если не заданы
    if args.model_path is None:
        args.model_path = model_path_for(args.model_type)
    json_path = meta_path_for(args.model_type)

    print("=" * 70)
    print(f"TRAINING {args.model_type.upper()} ON CICIDS-2017 "
          f"(fs={args.fs_method})")
    print("=" * 70)

    df = load_cicids(args.data_dir)
    df = clean_data(df)

    sil_top, sil_ranking = fs_silhouette(df, args.sample_fs, args.top_prefilter)
    rf_top, rf_importances = fs_rf_importance(df, args.sample_rf, args.top_prefilter)

    if args.fs_method == 'intersection':
        final_features = method_intersection(sil_top, rf_top, args.top_k)
    elif args.fs_method == 'rank_avg':
        final_features = method_rank_avg(sil_top, rf_top, args.top_k)
    elif args.fs_method == 'silhouette_only':
        final_features = method_silhouette_only(sil_top, args.top_k)

    blocks = split_features_by_block(final_features)
    print(f"\n[blocks] A/B/C: {len(blocks['A'])}/{len(blocks['B'])}/{len(blocks['C'])}")
    print(f"   A: {blocks['A']}")
    print(f"   B: {blocks['B']}")
    print(f"   C: {blocks['C']}")

    model, metrics = train_final(df, final_features, args.model_type)

    metrics['feature_selection'] = {
        'method': args.fs_method,
        'silhouette_top': sil_top,
        'rf_importance_top': rf_top,
        'intersection': [f for f in sil_top if f in set(rf_top)],
        'final_features': final_features,
        'blocks': blocks,
    }

    model.save(args.model_path, json_path=json_path, metrics=metrics)

    # Дописываем блоки в JSON
    with open(json_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    meta['features_by_block'] = blocks
    meta['selection_method'] = args.fs_method
    meta['model_type'] = args.model_type
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 70)
    print(f"DONE: {args.model_type.upper()}")
    print("=" * 70)
    print(f"Model:       {args.model_path}")
    print(f"Meta:        {json_path}")
    print(f"Features:    {final_features}")
    print(f"Accuracy:    {metrics['accuracy']:.4f}")
    print(f"F1:          {metrics['f1']:.4f}")
    print(f"ROC-AUC:     {metrics['roc_auc']}")


if __name__ == '__main__':
    main()
