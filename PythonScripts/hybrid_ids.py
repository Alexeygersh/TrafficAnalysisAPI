import numpy as np
import joblib
import json
import os
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List

# Порядок фич СТРОГО ФИКСИРОВАН — менять нельзя без переобучения модели
FEATURE_NAMES = [
    'PacketsPerSecond',   # [0] Скорость передачи пакетов (ключевой индикатор DoS)
    'AveragePacketSize',  # [1] Средний размер пакета
    'UniquePorts',        # [2] Количество уникальных портов назначения (сканирование)
    'TotalBytes',         # [3] Суммарный объём трафика
    'PacketCount',        # [4] Количество пакетов
    'DangerScore',        # [5] Оценка опасности из кластеризации (prior knowledge)
]

MODEL_VERSION = "1.0"


class HybridIDS:
    """
    Гибридная система обнаружения вторжений (IDS) уровня IP-источника.

    Комбинирует:
      - Random Forest (supervised)  — обнаружение известных паттернов атак
      - Isolation Forest (unsupervised) — обнаружение аномалий (zero-day)

    Работает на агрегированных метриках SOURCE-уровня (SourceMetrics),
    а не на отдельных пакетах — это соответствует подходу статистического
    анализа поведения хоста (Host Behavior Analysis).
    """

    def __init__(self):
        self.supervised: RandomForestClassifier = None
        self.anomaly_detector: IsolationForest = None
        self.scaler: StandardScaler = None
        self._is_loaded = False

    # ------------------------------------------------------------------
    # Обучение
    # ------------------------------------------------------------------

    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Обучение гибридной модели.

        Args:
            X_train: матрица фич (n_samples, 6), порядок — FEATURE_NAMES
            y_train: метки (0 = нормальный трафик, 1 = атака/аномалия)
        """
        print(f"[HybridIDS] Начало обучения: {X_train.shape[0]} образцов, "
              f"{X_train.shape[1]} фич")

        # 1. Нормализация
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)

        # 2. Random Forest — supervised-часть
        self.supervised = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',   # важно: данные могут быть несбалансированы
            random_state=42,
            n_jobs=1
        )
        self.supervised.fit(X_scaled, y_train)

        # 3. Isolation Forest — unsupervised-часть
        # Обучаем ТОЛЬКО на нормальном трафике — это ключевой момент:
        # модель запоминает, как выглядит норма, и потом ищет отклонения
        normal_mask = (y_train == 0)
        X_normal = X_scaled[normal_mask]

        if len(X_normal) < 10:
            print("[HybridIDS] WARNING: мало нормальных образцов для IsolationForest")
            X_normal = X_scaled  # fallback

        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,   # ожидаем ~10% аномалий в продакшн-трафике
            max_samples='auto',
            random_state=42,
            n_jobs=1
        )
        self.anomaly_detector.fit(X_normal)

        self._is_loaded = True

        # Быстрая оценка качества на обучающей выборке
        train_preds = self.supervised.predict(X_scaled)
        accuracy = np.mean(train_preds == y_train)
        print(f"[HybridIDS] Обучение завершено:")
        print(f"  Random Forest: {self.supervised.n_estimators} деревьев, "
              f"train accuracy = {accuracy:.3f}")
        print(f"  Isolation Forest: {self.anomaly_detector.n_estimators} деревьев, "
              f"обучен на {len(X_normal)} нормальных образцах")
        print(f"  Важность фич:")
        for name, importance in zip(FEATURE_NAMES,
                                     self.supervised.feature_importances_):
            print(f"    {name}: {importance:.3f}")

    # ------------------------------------------------------------------
    # Сохранение / загрузка
    # ------------------------------------------------------------------

    def save(self, model_path: str):
        """Сохраняет всю модель в один .pkl файл."""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        payload = {
            'version': MODEL_VERSION,
            'supervised': self.supervised,
            'anomaly_detector': self.anomaly_detector,
            'scaler': self.scaler,
            'feature_names': FEATURE_NAMES,
        }
        joblib.dump(payload, model_path)
        print(f"[HybridIDS] Модель сохранена: {model_path}")

    @classmethod
    def load(cls, model_path: str) -> 'HybridIDS':
        """Загружает модель из .pkl файла."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Файл модели не найден: {model_path}. "
                f"Запустите train_hybrid_model.py для обучения."
            )
        payload = joblib.load(model_path)
        instance = cls()
        instance.supervised = payload['supervised']
        instance.anomaly_detector = payload['anomaly_detector']
        instance.scaler = payload['scaler']
        instance._is_loaded = True
        print(f"[HybridIDS] Модель загружена: {model_path} "
              f"(версия {payload.get('version', '?')})")
        return instance

    # ------------------------------------------------------------------
    # Предсказание
    # ------------------------------------------------------------------

    def predict_batch(self, json_data: str) -> str:
        """
        Предсказание для списка источников трафика.
        Вызывается из C# через Python.NET.

        Args:
            json_data: JSON-строка, массив объектов с полями FEATURE_NAMES

        Returns:
            JSON-строка с результатами предсказания для каждого источника
        """
        sources = json.loads(json_data)
        results = []

        for source in sources:
            features = [
                float(source.get('PacketsPerSecond', 0.0)),
                float(source.get('AveragePacketSize', 0.0)),
                float(source.get('UniquePorts', 0)),
                float(source.get('TotalBytes', 0)),
                float(source.get('PacketCount', 0)),
                float(source.get('DangerScore', 0.0)),
            ]
            prediction = self._predict_single_features(features)
            prediction['sourceIP'] = source.get('SourceIP', '')
            results.append(prediction)

        return json.dumps(results)

    def predict_single_json(self, json_data: str) -> str:
        """
        Предсказание для одного источника.
        Вызывается из C# через Python.NET.

        Args:
            json_data: JSON-строка с полями FEATURE_NAMES

        Returns:
            JSON-строка с результатом
        """
        source = json.loads(json_data)
        features = [
            float(source.get('PacketsPerSecond', 0.0)),
            float(source.get('AveragePacketSize', 0.0)),
            float(source.get('UniquePorts', 0)),
            float(source.get('TotalBytes', 0)),
            float(source.get('PacketCount', 0)),
            float(source.get('DangerScore', 0.0)),
        ]
        return json.dumps(self._predict_single_features(features))

    def _predict_single_features(self, features: List[float]) -> Dict:
        """Внутренний метод предсказания для одного вектора фич."""
        if not self._is_loaded:
            raise RuntimeError(
                "Модель не загружена. Вызовите HybridIDS.load() или train()."
            )

        X = np.array(features, dtype=float).reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        # --- Random Forest ---
        rf_pred = int(self.supervised.predict(X_scaled)[0])        # 0 или 1
        rf_proba = float(self.supervised.predict_proba(X_scaled)[0, 1])  # P(атака)

        # --- Isolation Forest ---
        # Возвращает 1 (норма) или -1 (аномалия)
        if_raw = int(self.anomaly_detector.predict(X_scaled)[0])
        is_anomaly = 1 if if_raw == -1 else 0

        # --- Фьюжн-логика ---
        # Атака = RF видит атаку ИЛИ IF видит аномалию
        is_attack = bool(rf_pred == 1 or is_anomaly == 1)

        # --- Уровень угрозы — по уверенности RF ---
        if rf_proba >= 0.8:
            threat_level = 'Critical'
        elif rf_proba >= 0.6:
            threat_level = 'High'
        elif rf_proba >= 0.4:
            threat_level = 'Medium'
        else:
            threat_level = 'Low'

        # Если IF видит аномалию, но RF не видит атаку — повышаем до Medium
        # (на случай zero-day, о котором RF не знает)
        if is_anomaly == 1 and rf_pred == 0 and threat_level == 'Low':
            threat_level = 'Medium'

        # --- Метод обнаружения ---
        if is_anomaly == 1 and rf_pred == 0:
            method = 'unsupervised'   # zero-day: только IF нашёл
        elif is_anomaly == 1 and rf_pred == 1:
            method = 'both'           # известная атака + аномалия
        elif rf_pred == 1:
            method = 'supervised'     # только RF нашёл
        else:
            method = 'none'           # ни один не нашёл

        return {
            'isAttack': is_attack,
            'confidence': round(rf_proba, 4),
            'threatLevel': threat_level,
            'method': method,
            'rfPrediction': rf_pred,
            'isAnomaly': bool(is_anomaly),
        }
