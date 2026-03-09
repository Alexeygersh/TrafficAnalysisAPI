# optimized_clustering.py
import numpy as np
from sklearn.cluster import MiniBatchKMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any
import joblib
import os

class OptimizedClustering:
    """Оптимизированная кластеризация для NET"""
    
    # Синглтон для модели и scaler
    _scaler = None
    _kmeans = None
    _dbscan = None
    _is_fitted = False
    _feature_indices = None  # Индексы важных фичей
    
    @classmethod
    def load_or_create(cls, model_path='MLModels/clustering_model.pkl'):
        """Загрузка или создание модели"""
        if not os.path.exists(model_path):
            print("Clustering model not found, creating new one...")
            cls._scaler = StandardScaler()
            cls._kmeans = MiniBatchKMeans(
                n_clusters=5, 
                batch_size=100,
                max_iter=100,
                random_state=42,
                n_init=3  # Меньше инициализаций
            )
            cls._dbscan = DBSCAN(eps=0.5, min_samples=5)
            cls._is_fitted = False
            
            # Индексы важных фичей (можно вычислить через feature importance)
            cls._feature_indices = [0, 3, 4, 5, 6, 7, 10, 14]  # Пример
            
            cls.save(model_path)
        else:
            print("Loading existing clustering model...")
            model_data = joblib.load(model_path)
            cls._scaler = model_data['scaler']
            cls._kmeans = model_data['kmeans']
            cls._dbscan = model_data['dbscan']
            cls._is_fitted = model_data['is_fitted']
            cls._feature_indices = model_data['feature_indices']
        
        return cls
    
    @classmethod
    def save(cls, model_path='MLModels/clustering_model.pkl'):
        """Сохранение модели"""
        model_data = {
            'scaler': cls._scaler,
            'kmeans': cls._kmeans,
            'dbscan': cls._dbscan,
            'is_fitted': cls._is_fitted,
            'feature_indices': cls._feature_indices
        }
        joblib.dump(model_data, model_path)
        print(f"Clustering model saved to {model_path}")
    
    @classmethod
    def cluster_packets(cls, packets: List[Dict[str, Any]], algorithm='kmeans'):
        """
        Оптимизированная кластеризация пакетов
        
        Args:
            packets: Список пакетов
            algorithm: 'kmeans' или 'dbscan'
        
        Returns:
            List[int]: Индексы кластеров для каждого пакета
        """
        if len(packets) == 0:
            return []
        
        # ========================================
        # 1. Подготовка фичей (ВЕКТОРИЗОВАНО!)
        # ========================================
        # Базовые фичи
        flow_duration = np.array([p.get('flowDuration', 0) for p in packets])
        total_fwd_packets = np.array([p.get('totalFwdPackets', 0) for p in packets])
        total_backward_packets = np.array([p.get('totalBackwardPackets', 0) for p in packets])
        
        # Агрегированные фичи
        flow_bytes_per_second = np.array([p.get('flowBytesPerSecond', 0) for p in packets])
        flow_packets_per_second = np.array([p.get('flowPacketsPerSecond', 0) for p in packets])
        avg_packet_size = np.array([p.get('packetSize', 0) for p in packets])
        
        # Флаги и другие
        destination_port = np.array([p.get('port', 0) for p in packets])
        protocol_encoded = np.array([1 if p.get('protocol') == 'TCP' else 0 for p in packets])
        is_tcp = np.array([1 if p.get('protocol') == 'TCP' else 0 for p in packets])
        
        # ========================================
        # 2. Сборка всех фичей в одну матрицу
        # ========================================
        X = np.column_stack([
            flow_duration,
            total_fwd_packets,
            total_backward_packets,
            flow_bytes_per_second,      # Самый важный!
            flow_packets_per_second,     # Очень важный
            avg_packet_size,
            destination_port,
            protocol_encoded,
            is_tcp,
            flow_duration * flow_packets_per_second,  # Комбинация
            flow_bytes_per_second / (flow_packets_per_second + 1),  # Средний размер
            total_fwd_packets + total_backward_packets,  # Всего пакетов
            destination_port * protocol_encoded,  # Взаимодействие
            np.log1p(total_fwd_packets + 1)  # Логарифм (сглаживание)
        ])
        
        # ========================================
        # 3. Выбор важных фичей (если модель обучена)
        # ========================================
        if cls._feature_indices is not None:
            X = X[:, cls._feature_indices]
        
        # ========================================
        # 4. Нормализация (если есть scaler)
        # ========================================
        if cls._scaler is not None:
            X_scaled = cls._scaler.transform(X)
        else:
            X_scaled = X
        
        # ========================================
        # 5. Обучение (только первый раз!)
        # ========================================
        if not cls._is_fitted:
            print(f"Training clustering model on {len(X_scaled)} samples...")
            
            # Обучение K-Means (быстро из-за MiniBatch)
            cls._kmeans.fit(X_scaled)
            print(f"K-Means trained: {cls._kmeans.n_clusters} clusters")
            
            # Обучение DBSCAN (для выявления выбросов)
            cls._dbscan.fit(X_scaled)
            n_outliers = sum(cls._dbscan.labels_ == -1)
            print(f"DBSCAN trained: {n_outliers} outliers detected")
            
            cls._is_fitted = True
            
            # Автосохранение
            cls.save()
        
        # ========================================
        # 6. Предсказание (ВЕКТОРИЗОВАНО!)
        # ========================================
        if algorithm == 'kmeans':
            labels = cls._kmeans.predict(X_scaled)
        else:  # dbscan
            labels = cls._dbscan.labels_
        
        # ========================================
        # 7. Вычисление danger_score (ВЕКТОРИЗОВАНО!)
        # ========================================
        if algorithm == 'kmeans':
            # Расстояние до центроидов (векторизовано!)
            distances = np.linalg.norm(
                X_scaled - cls._kmeans.cluster_centers_[labels],
                axis=1
            )
            
            # Нормализация danger_score (0-1)
            max_distance = np.percentile(distances, 95)  # Robust max
            danger_scores = np.clip(distances / (max_distance + 1e-6), 0, 1)
        else:
            # Для DBSCAN: outliers = dangerous
            danger_scores = (labels == -1).astype(float)
        
        # ========================================
        # 8. Определение опасных кластеров (ВЕКТОРИЗОВАНО!)
        # ========================================
        if algorithm == 'kmeans':
            # Средний danger_score для каждого кластера
            cluster_danger = np.zeros(cls._kmeans.n_clusters)
            for i in range(cls._kmeans.n_clusters):
                mask = labels == i
                if np.any(mask):
                    cluster_danger[i] = np.mean(danger_scores[mask])
            
            # Опасные кластеры (выше среднего)
            avg_danger = np.mean(cluster_danger)
            is_dangerous = cluster_danger > (avg_danger + 0.2)  # На 20% выше среднего
            
            # Лейблы для каждого пакета
            is_dangerous_labels = is_dangerous[labels]
        else:
            # Для DBSCAN: outliers = dangerous
            is_dangerous_labels = (labels == -1).astype(int)
        
        # ========================================
        # 9. Подготовка результата
        # ========================================
        results = []
        for i, packet in enumerate(packets):
            results.append({
                'packetId': packet.get('id'),
                'clusterId': int(labels[i]) if labels[i] != -1 else -1,
                'dangerScore': float(danger_scores[i]),
                'isDangerous': bool(is_dangerous_labels[i]),
                'algorithm': algorithm
            })
        
        return results
    
    @classmethod
    def get_cluster_info(cls, cluster_id: int):
        """Информация о кластере"""
        if cls._kmeans is None:
            return None
        
        if cluster_id < 0 or cluster_id >= cls._kmeans.n_clusters:
            return None
        
        centroid = cls._kmeans.cluster_centers_[cluster_id]
        
        return {
            'clusterId': cluster_id,
            'centroid': centroid.tolist(),
            'size': np.sum(cls._kmeans.labels_ == cluster_id)
        }