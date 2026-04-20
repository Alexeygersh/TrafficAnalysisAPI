"""
PythonScripts/hybrid_ids.py  (v2.1, with in-process cache)

Гибридная IDS: Random Forest (supervised) + Isolation Forest (unsupervised).

Отличия от v1:
  - Список фичей НЕ хардкожен. Он сохраняется в .pkl и дублируется в .json
    рядом с моделью, чтобы C# мог прочитать его без Python.
  - `predict_batch` принимает произвольный набор полей во входных flows
    и сам отбирает нужные по именам.

Изменения в v2.1:
  - Добавлен модульный кеш моделей (_MODEL_CACHE) - загруженная модель
    остаётся в памяти Python-процесса между вызовами. Это убирает ~20 сек
    на повторные запросы от C# backend.

Формат .pkl (joblib):
  {
    'version': '2.0',
    'feature_names': ['SYNFlagCount', 'InitWinBytesForward', ...],
    'supervised':   RandomForestClassifier,
    'anomaly_detector': IsolationForest,
    'scaler': StandardScaler,
    'metrics': {'accuracy': ..., 'f1': ..., ...}   # опционально
  }

Плюс рядом лежит models/global_features.json:
  {"feature_names": [...], "model_version": "2.0", "trained_on": "CICIDS-2017"}
"""

import os
import json
import numpy as np
import joblib
from typing import Dict, List

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler


MODEL_VERSION = "2.0"

# ============================================================
# КЕШ НА УРОВНЕ МОДУЛЯ
# ============================================================
# Ключ: абсолютный путь к .pkl (+ mtime файла — чтобы обновлять при пересохранении)
# Значение: загруженный HybridIDS instance
# Python кеширует сам модуль через sys.modules, так что переменная живёт между
# вызовами Py.Import('hybrid_ids') из C#.
_MODEL_CACHE: Dict[str, 'HybridIDS'] = {}


def clear_cache():
    """Очистить весь кеш моделей. Полезно для тестов/после переобучения."""
    global _MODEL_CACHE
    _MODEL_CACHE.clear()
    print("[HybridIDS] Cache cleared")


class HybridIDS:
    def __init__(self):
        self.supervised: RandomForestClassifier = None
        self.anomaly_detector: IsolationForest = None
        self.scaler: StandardScaler = None
        self.feature_names: List[str] = []
        self._is_loaded = False

    # ------------------------------------------------------------------
    # Обучение
    # ------------------------------------------------------------------
    def train(self, X_train, y_train, feature_names: List[str]):
        assert X_train.shape[1] == len(feature_names), \
            f"X_train has {X_train.shape[1]} cols but got {len(feature_names)} names"

        self.feature_names = list(feature_names)

        print(f"[HybridIDS] Training on {X_train.shape[0]} samples, "
              f"{len(feature_names)} features")

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)

        self.supervised = RandomForestClassifier(
            n_estimators=200, max_depth=20,
            min_samples_split=5, min_samples_leaf=2,
            class_weight='balanced', random_state=42, n_jobs=-1,
        )
        self.supervised.fit(X_scaled, y_train)

        normal_mask = (y_train == 0)
        X_normal = X_scaled[normal_mask]
        if len(X_normal) < 10:
            print("[HybridIDS] WARN: мало нормальных образцов, используем все")
            X_normal = X_scaled

        self.anomaly_detector = IsolationForest(
            n_estimators=100, contamination=0.1,
            max_samples='auto', random_state=42, n_jobs=-1,
        )
        self.anomaly_detector.fit(X_normal)

        self._is_loaded = True

        print(f"\n[HybridIDS] Feature importances:")
        imp_pairs = sorted(
            zip(feature_names, self.supervised.feature_importances_),
            key=lambda x: -x[1]
        )
        for name, imp in imp_pairs:
            print(f"    {name:30s}  {imp:.4f}")

    # ------------------------------------------------------------------
    # Сохранение / загрузка
    # ------------------------------------------------------------------
    def save(self, model_path: str, json_path: str = None, metrics: Dict = None):
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        payload = {
            'version': MODEL_VERSION,
            'feature_names': self.feature_names,
            'supervised': self.supervised,
            'anomaly_detector': self.anomaly_detector,
            'scaler': self.scaler,
            'metrics': metrics or {},
        }
        joblib.dump(payload, model_path)
        print(f"[HybridIDS] Модель сохранена: {model_path}")

        # Сбрасываем кеш после сохранения — чтобы следующий load()
        # взял свежую версию, а не старую из памяти.
        abs_path = os.path.abspath(model_path)
        if abs_path in _MODEL_CACHE:
            del _MODEL_CACHE[abs_path]
            print(f"[HybridIDS] Cache invalidated for {abs_path}")

        if json_path is None:
            json_path = os.path.join(
                os.path.dirname(model_path), 'global_features.json')

        meta = {
            'feature_names': self.feature_names,
            'model_version': MODEL_VERSION,
            'model_file': os.path.basename(model_path),
            'trained_on': 'CICIDS-2017',
            'metrics': metrics or {},
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(f"[HybridIDS] Meta JSON: {json_path}")

    @classmethod
    def load(cls, model_path: str) -> 'HybridIDS':
        """
        Загружает модель из .pkl с кешированием.
        Если модель уже в кеше и файл не изменился - возвращает из кеша.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Файл модели не найден: {model_path}. "
                f"Сначала обучите через train_hybrid_model.py"
            )

        abs_path = os.path.abspath(model_path)
        mtime = os.path.getmtime(abs_path)
        cache_key = f"{abs_path}::{mtime}"

        # Ищем в кеше
        if cache_key in _MODEL_CACHE:
            print(f"[HybridIDS] CACHE HIT: {os.path.basename(abs_path)}")
            return _MODEL_CACHE[cache_key]

        # Cache miss или файл обновился — чистим старые ключи для этого пути
        stale_keys = [k for k in _MODEL_CACHE.keys() if k.startswith(abs_path + "::")]
        for k in stale_keys:
            del _MODEL_CACHE[k]

        # Реально загружаем с диска
        print(f"[HybridIDS] CACHE MISS: loading {os.path.basename(abs_path)}...")
        payload = joblib.load(abs_path)
        instance = cls()
        instance.supervised = payload['supervised']
        instance.anomaly_detector = payload['anomaly_detector']
        instance.scaler = payload['scaler']
        instance.feature_names = payload.get('feature_names', [])
        instance._is_loaded = True

        # Сохраняем в кеш
        _MODEL_CACHE[cache_key] = instance

        print(f"[HybridIDS] Загружена модель v{payload.get('version', '?')} "
              f"с {len(instance.feature_names)} признаками, закеширована")
        return instance

    # ------------------------------------------------------------------
    # Предсказание
    # ------------------------------------------------------------------
    def _predict_vector(self, features_vec: List[float]) -> Dict:
        X = np.array(features_vec, dtype=float).reshape(1, -1)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = self.scaler.transform(X)

        rf_pred = int(self.supervised.predict(X_scaled)[0])
        rf_proba = float(self.supervised.predict_proba(X_scaled)[0, 1])

        if_raw = int(self.anomaly_detector.predict(X_scaled)[0])
        is_anomaly = 1 if if_raw == -1 else 0

        is_attack = bool(rf_pred == 1 or is_anomaly == 1)

        if rf_proba >= 0.8:
            threat = 'Critical'
        elif rf_proba >= 0.6:
            threat = 'High'
        elif rf_proba >= 0.4:
            threat = 'Medium'
        else:
            threat = 'Low'

        if is_anomaly == 1 and rf_pred == 0 and threat == 'Low':
            threat = 'Medium'

        if is_anomaly == 1 and rf_pred == 0:
            method = 'unsupervised'
        elif is_anomaly == 1 and rf_pred == 1:
            method = 'both'
        elif rf_pred == 1:
            method = 'supervised'
        else:
            method = 'none'

        return {
            'isAttack': is_attack,
            'confidence': round(rf_proba, 4),
            'threatLevel': threat,
            'method': method,
            'rfPrediction': rf_pred,
            'isAnomaly': bool(is_anomaly),
        }

    def predict_batch(self, json_data: str) -> str:
        """
        Batch-предсказание для списка flows. Векторизованный вызов —
        быстрее чем по одному.
        """
        if not self._is_loaded:
            raise RuntimeError("Модель не загружена. Вызовите HybridIDS.load()")

        items = json.loads(json_data)
        if not items:
            return json.dumps([])

        # Собираем матрицу фичей для batch-инференса
        feat_matrix = []
        for item in items:
            vec = []
            for feat in self.feature_names:
                val = item.get(feat)
                if val is None:
                    camel = feat[0].lower() + feat[1:]
                    val = item.get(camel, 0.0)
                try:
                    vec.append(float(val) if val is not None else 0.0)
                except (TypeError, ValueError):
                    vec.append(0.0)
            feat_matrix.append(vec)

        X = np.array(feat_matrix, dtype=float)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = self.scaler.transform(X)

        # Батч-инференс — гораздо быстрее чем N одиночных вызовов
        rf_preds = self.supervised.predict(X_scaled)
        rf_probas = self.supervised.predict_proba(X_scaled)[:, 1]
        if_raw = self.anomaly_detector.predict(X_scaled)

        results = []
        for i, item in enumerate(items):
            rf_pred = int(rf_preds[i])
            rf_proba = float(rf_probas[i])
            is_anomaly = 1 if int(if_raw[i]) == -1 else 0

            is_attack = bool(rf_pred == 1 or is_anomaly == 1)

            if rf_proba >= 0.8:
                threat = 'Critical'
            elif rf_proba >= 0.6:
                threat = 'High'
            elif rf_proba >= 0.4:
                threat = 'Medium'
            else:
                threat = 'Low'

            if is_anomaly == 1 and rf_pred == 0 and threat == 'Low':
                threat = 'Medium'

            if is_anomaly == 1 and rf_pred == 0:
                method = 'unsupervised'
            elif is_anomaly == 1 and rf_pred == 1:
                method = 'both'
            elif rf_pred == 1:
                method = 'supervised'
            else:
                method = 'none'

            results.append({
                'isAttack': is_attack,
                'confidence': round(rf_proba, 4),
                'threatLevel': threat,
                'method': method,
                'rfPrediction': rf_pred,
                'isAnomaly': bool(is_anomaly),
                'sourceIP': item.get('SourceIP', item.get('sourceIP', '')),
                'destinationIP': item.get('DestinationIP',
                                          item.get('destinationIP', '')),
                'destinationPort': int(
                    item.get('DestinationPort',
                             item.get('destinationPort', 0)) or 0),
                'protocol': item.get('Protocol', item.get('protocol', '')),
            })

        return json.dumps(results)
