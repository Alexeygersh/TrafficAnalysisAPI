"""
PythonScripts/catboost_ids.py

Гибридная IDS с CatBoost вместо Random Forest.
Структура полностью зеркалит hybrid_ids.py для совместимости:
  - Тот же интерфейс (train, save, load, predict_batch)
  - Тот же формат .pkl
  - Тот же кеш моделей
  - Тот же JSON-ответ

Отличия:
  - supervised: CatBoostClassifier вместо RandomForestClassifier
  - Ожидается что CatBoost даст более точные вероятности (calibrated probas)

Запуск обучения:
  python train_hybrid_model.py --model_type catboost
"""

import os
import json
import numpy as np
import joblib
from typing import Dict, List

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from catboost import CatBoostClassifier


MODEL_VERSION = "2.0-catboost"

# Отдельный кеш для CatBoost моделей (не смешиваем с hybrid_ids)
_CB_MODEL_CACHE: Dict[str, 'CatBoostIDS'] = {}


def clear_cache():
    global _CB_MODEL_CACHE
    _CB_MODEL_CACHE.clear()
    print("[CatBoostIDS] Cache cleared")


class CatBoostIDS:
    def __init__(self):
        self.supervised: CatBoostClassifier = None
        self.anomaly_detector: IsolationForest = None
        self.scaler: StandardScaler = None
        self.feature_names: List[str] = []
        self._is_loaded = False

    # ------------------------------------------------------------------
    def train(self, X_train, y_train, feature_names: List[str]):
        assert X_train.shape[1] == len(feature_names), \
            f"X_train has {X_train.shape[1]} cols but got {len(feature_names)} names"

        self.feature_names = list(feature_names)

        print(f"[CatBoostIDS] Training on {X_train.shape[0]} samples, "
              f"{len(feature_names)} features")

        # CatBoost работает лучше без стандартизации, но мы скейлим для консистентности
        # с hybrid_ids (чтобы IF работал на тех же scaled-данных)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)

        # Баланс классов
        class_counts = np.bincount(y_train)
        if len(class_counts) == 2:
            # class_weights = [weight_for_class_0, weight_for_class_1]
            # Balanced: обратная пропорциональность частоте
            total = class_counts.sum()
            class_weights = [total / (2 * class_counts[0]),
                             total / (2 * class_counts[1])]
        else:
            class_weights = None

        self.supervised = CatBoostClassifier(
            iterations=200,           # deepening iterations
            learning_rate=0.05,
            depth=8,
            l2_leaf_reg=3,
            class_weights=class_weights,
            eval_metric='F1',
            random_seed=42,
            verbose=100,              # Печатать прогресс раз в 100 итераций
            allow_writing_files=False,  # не создаёт catboost_info/
            thread_count=-1,
        )

        # CatBoost умеет сам использовать eval set — используем часть train
        # для раннего останова. Но для простоты пока без этого.
        self.supervised.fit(X_scaled, y_train)

        # IsolationForest на норме (как в hybrid_ids)
        normal_mask = (y_train == 0)
        X_normal = X_scaled[normal_mask]
        if len(X_normal) < 10:
            print("[CatBoostIDS] WARN: мало нормальных образцов")
            X_normal = X_scaled

        self.anomaly_detector = IsolationForest(
            n_estimators=100, contamination=0.1,
            max_samples='auto', random_state=42, n_jobs=-1,
        )
        self.anomaly_detector.fit(X_normal)

        self._is_loaded = True

        print(f"\n[CatBoostIDS] Feature importances:")
        imp_pairs = sorted(
            zip(feature_names, self.supervised.feature_importances_),
            key=lambda x: -x[1]
        )
        for name, imp in imp_pairs:
            print(f"    {name:30s}  {imp:.4f}")

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
        print(f"[CatBoostIDS] Модель сохранена: {model_path}")

        # Инвалидируем кеш
        abs_path = os.path.abspath(model_path)
        stale = [k for k in _CB_MODEL_CACHE.keys() if k.startswith(abs_path + "::")]
        for k in stale:
            del _CB_MODEL_CACHE[k]

        if json_path is None:
            json_path = os.path.join(
                os.path.dirname(model_path), 'catboost_features.json')

        meta = {
            'feature_names': self.feature_names,
            'model_version': MODEL_VERSION,
            'model_file': os.path.basename(model_path),
            'trained_on': 'CICIDS-2017',
            'metrics': metrics or {},
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(f"[CatBoostIDS] Meta JSON: {json_path}")

    @classmethod
    def load(cls, model_path: str) -> 'CatBoostIDS':
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Файл модели CatBoost не найден: {model_path}. "
                f"Обучите через train_hybrid_model.py --model_type catboost"
            )

        abs_path = os.path.abspath(model_path)
        mtime = os.path.getmtime(abs_path)
        cache_key = f"{abs_path}::{mtime}"

        if cache_key in _CB_MODEL_CACHE:
            print(f"[CatBoostIDS] CACHE HIT: {os.path.basename(abs_path)}")
            return _CB_MODEL_CACHE[cache_key]

        stale = [k for k in _CB_MODEL_CACHE.keys()
                 if k.startswith(abs_path + "::")]
        for k in stale:
            del _CB_MODEL_CACHE[k]

        print(f"[CatBoostIDS] CACHE MISS: loading {os.path.basename(abs_path)}...")
        payload = joblib.load(abs_path)
        instance = cls()
        instance.supervised = payload['supervised']
        instance.anomaly_detector = payload['anomaly_detector']
        instance.scaler = payload['scaler']
        instance.feature_names = payload.get('feature_names', [])
        instance._is_loaded = True

        _CB_MODEL_CACHE[cache_key] = instance

        print(f"[CatBoostIDS] Загружена модель v{payload.get('version', '?')} "
              f"с {len(instance.feature_names)} признаками")
        return instance

    # ------------------------------------------------------------------
    def predict_batch(self, json_data: str) -> str:
        if not self._is_loaded:
            raise RuntimeError("Модель не загружена. Вызовите CatBoostIDS.load()")

        items = json.loads(json_data)
        if not items:
            return json.dumps([])

        # Матрица фичей
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

        # Батч-инференс
        cb_preds = self.supervised.predict(X_scaled).flatten().astype(int)
        cb_probas = self.supervised.predict_proba(X_scaled)[:, 1]
        if_raw = self.anomaly_detector.predict(X_scaled)

        results = []
        for i, item in enumerate(items):
            cb_pred = int(cb_preds[i])
            cb_proba = float(cb_probas[i])
            is_anomaly = 1 if int(if_raw[i]) == -1 else 0

            is_attack = bool(cb_pred == 1 or is_anomaly == 1)

            if cb_proba >= 0.8:
                threat = 'Critical'
            elif cb_proba >= 0.6:
                threat = 'High'
            elif cb_proba >= 0.4:
                threat = 'Medium'
            else:
                threat = 'Low'

            if is_anomaly == 1 and cb_pred == 0 and threat == 'Low':
                threat = 'Medium'

            if is_anomaly == 1 and cb_pred == 0:
                method = 'unsupervised'
            elif is_anomaly == 1 and cb_pred == 1:
                method = 'both'
            elif cb_pred == 1:
                method = 'supervised'
            else:
                method = 'none'

            results.append({
                'isAttack': is_attack,
                'confidence': round(cb_proba, 4),
                'threatLevel': threat,
                'method': method,
                'rfPrediction': cb_pred,  # оставляем имя "rfPrediction" для совместимости DTO
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
