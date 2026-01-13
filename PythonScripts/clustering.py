import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
import base64
from io import BytesIO
import seaborn as sns


def visualize_clusters(json_data):
    """Создает 2D scatter plot кластеров с использованием PCA"""
    data = json.loads(json_data)
    
    print(f"--Visualizing {len(data)} sources")
    
    if len(data) < 2:
        return json.dumps({'error': 'Not enough data for visualization'})
    
    # Извлекаем признаки
    features = np.array([[
        float(item.get('packetsPerSecond', 0.0)),
        int(item.get('packetCount', 0)),
        float(item.get('averagePacketSize', 0.0)),
        int(item.get('uniquePorts', 0))
    ] for item in data])
    
    cluster_ids = np.array([item['clusterId'] for item in data])
    is_dangerous = np.array([item['isDangerous'] for item in data])
    danger_scores = np.array([item['dangerScore'] for item in data])
    
    # Нормализация и PCA
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    pca = PCA(n_components=2)
    features_2d = pca.fit_transform(features_scaled)
    
    # Создаем график
    plt.figure(figsize=(14, 10))
    
    # Получаем уникальные кластеры
    unique_clusters = np.unique(cluster_ids)
    n_clusters = len(unique_clusters)
    
    # Цветовая палитра для кластеров
    colors = plt.cm.tab10(np.linspace(0, 1, max(10, n_clusters)))
    
    # Отрисовываем каждый кластер отдельно
    for idx, cluster_id in enumerate(unique_clusters):
        mask = cluster_ids == cluster_id
        cluster_color = colors[idx % len(colors)]
        
        # Определяем, опасный ли кластер
        cluster_is_dangerous = is_dangerous[mask][0] if np.any(mask) else False
        
        # Размер точек зависит от опасности
        point_size = 300 if cluster_is_dangerous else 150
        edge_width = 3 if cluster_is_dangerous else 1
        edge_color = 'red' if cluster_is_dangerous else 'black'
        
        # Метка кластера
        cluster_label = f'Cluster {cluster_id}'
        if cluster_is_dangerous:
            cluster_label += ' [DANGER]'
        
        # Рисуем точки кластера
        scatter = plt.scatter(
            features_2d[mask, 0], 
            features_2d[mask, 1],
            c=[cluster_color] * np.sum(mask),
            s=point_size,
            alpha=0.7,
            edgecolors=edge_color,
            linewidths=edge_width,
            label=cluster_label
        )
        
        # Подписываем опасные точки
        for i, is_danger_point in enumerate(is_dangerous[mask]):
            point_idx = np.where(mask)[0][i]
            if is_danger_point:
                ip_address = data[point_idx]['sourceIP']
                danger_score_text = f"{danger_scores[point_idx]:.2f}"
                annotation_text = f"{ip_address}\nScore: {danger_score_text}"
                
                plt.annotate(
                    annotation_text,
                    (features_2d[point_idx, 0], features_2d[point_idx, 1]),
                    fontsize=9,
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='yellow', alpha=0.7),
                    ha='center'
                )
    
    # Оформление графика
    variance_1 = pca.explained_variance_ratio_[0] * 100
    variance_2 = pca.explained_variance_ratio_[1] * 100
    
    plt.xlabel(f'PC1 ({variance_1:.1f}% variance)', fontsize=14, fontweight='bold')
    plt.ylabel(f'PC2 ({variance_2:.1f}% variance)', fontsize=14, fontweight='bold')
    plt.title(f'Source Clustering Visualization ({n_clusters} clusters)', fontsize=16, fontweight='bold')
    plt.legend(fontsize=11, loc='best', framealpha=0.9)
    plt.grid(True, alpha=0.3, linestyle='--')
    
    # Сохраняем в Base64
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode()
    plt.close()
    
    print(f"--Visualization created successfully with {n_clusters} clusters")
    
    # Обработка NaN
    variance_ratio_1 = float(pca.explained_variance_ratio_[0])
    variance_ratio_2 = float(pca.explained_variance_ratio_[1])
    
    if np.isnan(variance_ratio_1):
        variance_ratio_1 = 0.0
    if np.isnan(variance_ratio_2):
        variance_ratio_2 = 0.0
    
    total_variance = variance_ratio_1 + variance_ratio_2
    if np.isnan(total_variance):
        total_variance = 0.0
    
    return json.dumps({
        'image': f'data:image/png;base64,{image_base64}',
        'explainedVariance': [variance_ratio_1, variance_ratio_2],
        'totalVarianceExplained': total_variance
    })


def cluster_sources(json_data, method='kmeans', n_clusters=3):
    data = json.loads(json_data)
    
    print(f"--Received {len(data)} sources for clustering")
    print(f"--Method: {method}, Requested clusters: {n_clusters}")
    
    if len(data) < 2:
        print("! Less than 2 sources, returning single cluster")
        return json.dumps([{
            **item, 
            'clusterId': 1,
            'isDangerous': False,
            'dangerScore': 0.0,
            'clusterName': 'Cluster 1'
        } for item in data])
    
    features = np.array([
        [
            float(item.get('PacketsPerSecond', 0.0)),
            int(item.get('PacketCount', 0)),
            float(item.get('AveragePacketSize', 0.0)),
            int(item.get('UniquePorts', 0))
        ] 
        for item in data
    ])
    
    print(f"--Features shape: {features.shape}")
    print(f"--Sample features (first 3):\n{features[:3]}")

    if np.all(features == 0):
        print("! All features are zero!")
        return json.dumps([{
            **item, 
            'clusterId': 1,
            'isDangerous': False,
            'dangerScore': 0.0,
            'clusterName': 'Cluster 1'
        } for item in data])
    
    # normalization
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    print(f"--Normalized features (first 3):\n{features_scaled[:3]}")
    
    # clusterization
    if method == 'kmeans':
        n_clusters = min(n_clusters, len(data))
        print(f"--Using K-Means with k={n_clusters}")
        clusterer = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    else:
        print(f"--Using DBSCAN")
        clusterer = DBSCAN(eps=0.5, min_samples=2)
    
    cluster_ids = clusterer.fit_predict(features_scaled)
    
    print(f"--Raw cluster IDs from sklearn: {cluster_ids}")
    print(f"--Unique clusters from sklearn: {set(cluster_ids)}")
    
    # 0,1,2 -> 1,2,3 (-1,0,1 -> 1,2,3 DBSCAN)
    unique_ids = sorted(set(cluster_ids))
    id_mapping = {old_id: new_id + 1 for new_id, old_id in enumerate(unique_ids)}
    
    print(f"--ID Mapping: {id_mapping}")
    
    # mapping
    cluster_ids_remapped = np.array([id_mapping[old_id] for old_id in cluster_ids])
    
    print(f"--Remapped cluster IDs: {cluster_ids_remapped}")
    print(f"--Final unique clusters: {set(cluster_ids_remapped)}")
    
    # Calculate danger (remapped IDs)
    cluster_stats = calculate_cluster_danger(data, cluster_ids_remapped)
    
    results = []
    for i, item in enumerate(data):
        cluster_id = int(cluster_ids_remapped[i])
        stats = cluster_stats.get(cluster_id, {
            'dangerScore': 0.0, 
            'isDangerous': False, 
            'name': f'Cluster {cluster_id}'
        })
        
        result_item = {
            **item,
            'clusterId': int(cluster_id),
            'isDangerous': bool(stats['isDangerous']),
            'dangerScore': float(stats['dangerScore']),
            'clusterName': str(stats['name'])
        }
        results.append(result_item)
    
    print(f"--Returning {len(results)} clustered sources")
    return json.dumps(results, default=str)


def calculate_cluster_danger(data, cluster_ids):
    clusters = {}
    
    for i, cluster_id in enumerate(cluster_ids):
        if cluster_id not in clusters:
            clusters[cluster_id] = {
                'speeds': [],
                'packet_counts': [],
                'port_diversity': []
            }
        
        item = data[i]
        clusters[cluster_id]['speeds'].append(float(item.get('PacketsPerSecond', 0.0)))
        clusters[cluster_id]['packet_counts'].append(int(item.get('PacketCount', 0)))
        clusters[cluster_id]['port_diversity'].append(int(item.get('UniquePorts', 0)))
    
    cluster_stats = {}
    
    all_speeds = [s for c in clusters.values() for s in c['speeds']]
    all_diversity = [d for c in clusters.values() for d in c['port_diversity']]
    
    max_speed = max(all_speeds) if all_speeds and max(all_speeds) > 0 else 1.0
    max_diversity = max(all_diversity) if all_diversity and max(all_diversity) > 0 else 1.0
    
    for cluster_id, stats in clusters.items():
        avg_speed = np.mean(stats['speeds']) if stats['speeds'] else 0.0
        avg_diversity = np.mean(stats['port_diversity']) if stats['port_diversity'] else 0.0
        max_cluster_speed = max(stats['speeds']) if stats['speeds'] else 0.0
        
        danger_score = (
            0.5 * (max_cluster_speed / max_speed) +
            0.3 * (avg_diversity / max_diversity) +
            0.2 * (len(stats['speeds']) / len(data))
        )
        
        cluster_stats[cluster_id] = {
            'dangerScore': float(danger_score),
            'isDangerous': danger_score > 0.6,
            'name': get_cluster_name(cluster_id, danger_score)
        }
    
    return cluster_stats


def get_cluster_name(cluster_id, danger_score):
    if danger_score > 0.8:
        return f"Critical Cluster {cluster_id}"
    elif danger_score > 0.6:
        return f"High Risk Cluster {cluster_id}"
    elif danger_score > 0.4:
        return f"Medium Risk Cluster {cluster_id}"
    else:
        return f"Low Risk Cluster {cluster_id}"



"""
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
import json

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
import base64
from io import BytesIO
import seaborn as sns


def visualize_clusters(json_data):
    #Создает 2D scatter plot кластеров с использованием PCA
    data = json.loads(json_data)
    
    print(f"--Visualizing {len(data)} sources")
    
    if len(data) < 2:
        return json.dumps({'error': 'Not enough data for visualization'})
    
    features = np.array([[
        float(item.get('packetsPerSecond', 0.0)),
        int(item.get('packetCount', 0)),
        float(item.get('averagePacketSize', 0.0)),
        int(item.get('uniquePorts', 0))
    ] for item in data])
    
    cluster_ids = np.array([item['clusterId'] for item in data])
    is_dangerous = np.array([item['isDangerous'] for item in data])
    danger_scores = np.array([item['dangerScore'] for item in data])
    
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    pca = PCA(n_components=2)
    features_2d = pca.fit_transform(features_scaled)
    
    plt.figure(figsize=(12, 8))
    
    dangerous_mask = is_dangerous
    safe_mask = ~dangerous_mask
    
    if np.any(dangerous_mask):
        scatter_danger = plt.scatter(
            features_2d[dangerous_mask, 0], 
            features_2d[dangerous_mask, 1],
            c=danger_scores[dangerous_mask],
            cmap='Reds',
            s=200,
            alpha=0.7,
            edgecolors='darkred',
            linewidths=2,
            label='Dangerous',
            vmin=0, vmax=1
        )
        
        for i, is_danger in enumerate(dangerous_mask):
            if is_danger:
                plt.annotate(
                    f"{data[i]['sourceIP']}\n({danger_scores[i]:.2f})",
                    (features_2d[i, 0], features_2d[i, 1]),
                    fontsize=8,
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.5),
                    ha='center'
                )
    
    if np.any(safe_mask):
        plt.scatter(
            features_2d[safe_mask, 0], 
            features_2d[safe_mask, 1],
            c='green',
            s=100,
            alpha=0.5,
            edgecolors='darkgreen',
            linewidths=1,
            label='Safe'
        )
    
    plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)', fontsize=12)
    plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)', fontsize=12)
    plt.title('Source Clustering Visualization (2D PCA Projection)', fontsize=14, fontweight='bold')
    plt.legend(fontsize=10)
    plt.grid(True, alpha=0.3, linestyle='--')
    
    if np.any(dangerous_mask):
        cbar = plt.colorbar(scatter_danger)
        cbar.set_label('Danger Score', fontsize=10)
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode()
    plt.close()
    
    print(f"--Visualization created successfully")
    
    # Обработка NaN
    variance_ratio_1 = float(pca.explained_variance_ratio_[0])
    variance_ratio_2 = float(pca.explained_variance_ratio_[1])
    
    if np.isnan(variance_ratio_1):
        variance_ratio_1 = 0.0
    if np.isnan(variance_ratio_2):
        variance_ratio_2 = 0.0
    
    total_variance = variance_ratio_1 + variance_ratio_2
    if np.isnan(total_variance):
        total_variance = 0.0
    
    return json.dumps({
        'image': f'data:image/png;base64,{image_base64}',
        'explainedVariance': [variance_ratio_1, variance_ratio_2],
        'totalVarianceExplained': total_variance
    })


def create_cluster_heatmap(json_data):
    #Создает heatmap характеристик кластеров
    data = json.loads(json_data)
    
    if len(data) < 2:
        return json.dumps({'error': 'Not enough data'})
    
    clusters = {}
    for item in data:
        cluster_id = item['clusterId']
        
        if cluster_id not in clusters:
            clusters[cluster_id] = {
                'PacketsPerSecond': [],
                'PacketCount': [],
                'AveragePacketSize': [],
                'UniquePorts': [],
                'DangerScore': []
            }
        
        clusters[cluster_id]['PacketsPerSecond'].append(item['packetsPerSecond'])
        clusters[cluster_id]['PacketCount'].append(item['packetCount'])
        clusters[cluster_id]['AveragePacketSize'].append(item['averagePacketSize'])
        clusters[cluster_id]['UniquePorts'].append(item['uniquePorts'])
        clusters[cluster_id]['DangerScore'].append(item['dangerScore'])
    
    cluster_ids = sorted(clusters.keys())
    heatmap_data = []
    
    for cluster_id in cluster_ids:
        heatmap_data.append([
            np.mean(clusters[cluster_id]['PacketsPerSecond']),
            np.mean(clusters[cluster_id]['PacketCount']),
            np.mean(clusters[cluster_id]['AveragePacketSize']),
            np.mean(clusters[cluster_id]['UniquePorts']),
            np.mean(clusters[cluster_id]['DangerScore'])
        ])
    
    heatmap_array = np.array(heatmap_data)
    heatmap_normalized = (heatmap_array - heatmap_array.min(axis=0)) / \
                         (heatmap_array.max(axis=0) - heatmap_array.min(axis=0) + 1e-8)
    
    plt.figure(figsize=(10, 6))
    
    sns.heatmap(
        heatmap_normalized,
        annot=True,
        fmt='.2f',
        cmap='RdYlGn_r',
        xticklabels=['PPS', 'Count', 'Avg Size', 'Ports', 'Danger'],
        yticklabels=[f'Cluster {cid}' for cid in cluster_ids],
        cbar_kws={'label': 'Normalized Value'}
    )
    
    plt.title('Cluster Characteristics Heatmap', fontsize=14, fontweight='bold')
    plt.xlabel('Metrics', fontsize=12)
    plt.ylabel('Clusters', fontsize=12)
    plt.tight_layout()
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode()
    plt.close()
    
    return json.dumps({
        'image': f'data:image/png;base64,{image_base64}'
    })


def create_danger_timeline(json_data):
    #Создает timeline активности по кластерам
    data = json.loads(json_data)
    
    if len(data) < 2:
        return json.dumps({'error': 'Not enough data'})
    
    cluster_stats = {}
    for item in data:
        cluster_id = item['clusterId']
        
        if cluster_id not in cluster_stats:
            cluster_stats[cluster_id] = {
                'sources': 0,
                'total_pps': 0,
                'danger_score': 0,
                'is_dangerous': item['isDangerous']
            }
        
        cluster_stats[cluster_id]['sources'] += 1
        cluster_stats[cluster_id]['total_pps'] += item['packetsPerSecond']
        cluster_stats[cluster_id]['danger_score'] += item['dangerScore']
    
    for cluster_id in cluster_stats:
        n = cluster_stats[cluster_id]['sources']
        cluster_stats[cluster_id]['avg_pps'] = cluster_stats[cluster_id]['total_pps'] / n
        cluster_stats[cluster_id]['avg_danger'] = cluster_stats[cluster_id]['danger_score'] / n
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
    
    cluster_ids = sorted(cluster_stats.keys())
    colors = ['red' if cluster_stats[cid]['is_dangerous'] else 'green' 
              for cid in cluster_ids]
    
    ax1.bar(
        [f'Cluster {cid}' for cid in cluster_ids],
        [cluster_stats[cid]['sources'] for cid in cluster_ids],
        color=colors,
        alpha=0.7,
        edgecolor='black'
    )
    ax1.set_ylabel('Number of Sources', fontsize=11)
    ax1.set_title('Sources per Cluster', fontsize=12, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    ax2.bar(
        [f'Cluster {cid}' for cid in cluster_ids],
        [cluster_stats[cid]['avg_danger'] for cid in cluster_ids],
        color=colors,
        alpha=0.7,
        edgecolor='black'
    )
    ax2.set_ylabel('Average Danger Score', fontsize=11)
    ax2.set_xlabel('Cluster', fontsize=11)
    ax2.set_title('Danger Score by Cluster', fontsize=12, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    ax2.axhline(y=0.6, color='orange', linestyle='--', label='Danger Threshold')
    ax2.legend()
    
    plt.tight_layout()
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode()
    plt.close()
    
    return json.dumps({
        'image': f'data:image/png;base64,{image_base64}'
    })


def cluster_sources(json_data, method='kmeans', n_clusters=3):
    data = json.loads(json_data)
    
    print(f"--Received {len(data)} sources for clustering")
    print(f"--Method: {method}, Requested clusters: {n_clusters}")
    
    if len(data) < 2:
        print("! Less than 2 sources, returning single cluster")
        return json.dumps([{
            **item, 
            'clusterId': 1,
            'isDangerous': False,
            'dangerScore': 0.0,
            'clusterName': 'Cluster 1'
        } for item in data])
    
    features = np.array([
        [
            float(item.get('PacketsPerSecond', 0.0)),
            int(item.get('PacketCount', 0)),
            float(item.get('AveragePacketSize', 0.0)),
            int(item.get('UniquePorts', 0))
        ] 
        for item in data
    ])
    
    print(f"--Features shape: {features.shape}")
    print(f"--Sample features (first 3):\n{features[:3]}")

    if np.all(features == 0):
        print("! All features are zero!")
        return json.dumps([{
            **item, 
            'clusterId': 1,
            'isDangerous': False,
            'dangerScore': 0.0,
            'clusterName': 'Cluster 1'
        } for item in data])
    
    # normalization
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    print(f"--Normalized features (first 3):\n{features_scaled[:3]}")
    
    # clusterization
    if method == 'kmeans':
        n_clusters = min(n_clusters, len(data))
        print(f"--Using K-Means with k={n_clusters}")
        clusterer = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    else:
        print(f"--Using DBSCAN")
        clusterer = DBSCAN(eps=0.5, min_samples=2)
    
    cluster_ids = clusterer.fit_predict(features_scaled)
    
    print(f"--Raw cluster IDs from sklearn: {cluster_ids}")
    print(f"--Unique clusters from sklearn: {set(cluster_ids)}")
    
    # 0,1,2 -> 1,2,3 (-1,0,1 -> 1,2,3 DBSCAN)
    unique_ids = sorted(set(cluster_ids))
    id_mapping = {old_id: new_id + 1 for new_id, old_id in enumerate(unique_ids)}
    
    print(f"--ID Mapping: {id_mapping}")
    
    # mapping
    cluster_ids_remapped = np.array([id_mapping[old_id] for old_id in cluster_ids])
    
    print(f"--Remapped cluster IDs: {cluster_ids_remapped}")
    print(f"--Final unique clusters: {set(cluster_ids_remapped)}")
    
    # Calculate danger (remapped IDs)
    cluster_stats = calculate_cluster_danger(data, cluster_ids_remapped)
    
    results = []
    for i, item in enumerate(data):
        cluster_id = int(cluster_ids_remapped[i])
        stats = cluster_stats.get(cluster_id, {
            'dangerScore': 0.0, 
            'isDangerous': False, 
            'name': f'Cluster {cluster_id}'
        })
        
        result_item = {
            **item,
            'clusterId': int(cluster_id),
            'isDangerous': bool(stats['isDangerous']),
            'dangerScore': float(stats['dangerScore']),
            'clusterName': str(stats['name'])
        }
        results.append(result_item)
    
    print(f"--Returning {len(results)} clustered sources")
    return json.dumps(results, default=str)


def calculate_cluster_danger(data, cluster_ids):
    clusters = {}
    
    for i, cluster_id in enumerate(cluster_ids):
        if cluster_id not in clusters:
            clusters[cluster_id] = {
                'speeds': [],
                'packet_counts': [],
                'port_diversity': []
            }
        
        item = data[i]
        clusters[cluster_id]['speeds'].append(float(item.get('PacketsPerSecond', 0.0)))
        clusters[cluster_id]['packet_counts'].append(int(item.get('PacketCount', 0)))
        clusters[cluster_id]['port_diversity'].append(int(item.get('UniquePorts', 0)))
    
    cluster_stats = {}
    
    all_speeds = [s for c in clusters.values() for s in c['speeds']]
    all_diversity = [d for c in clusters.values() for d in c['port_diversity']]
    
    max_speed = max(all_speeds) if all_speeds and max(all_speeds) > 0 else 1.0
    max_diversity = max(all_diversity) if all_diversity and max(all_diversity) > 0 else 1.0
    
    for cluster_id, stats in clusters.items():
        avg_speed = np.mean(stats['speeds']) if stats['speeds'] else 0.0
        avg_diversity = np.mean(stats['port_diversity']) if stats['port_diversity'] else 0.0
        max_cluster_speed = max(stats['speeds']) if stats['speeds'] else 0.0
        
        danger_score = (
            0.5 * (max_cluster_speed / max_speed) +
            0.3 * (avg_diversity / max_diversity) +
            0.2 * (len(stats['speeds']) / len(data))
        )
        
        cluster_stats[cluster_id] = {
            'dangerScore': float(danger_score),
            'isDangerous': danger_score > 0.6,
            'name': get_cluster_name(cluster_id, danger_score)
        }
    
    return cluster_stats


def get_cluster_name(cluster_id, danger_score):
    if danger_score > 0.8:
        return f"Critical Cluster {cluster_id}"
    elif danger_score > 0.6:
        return f"High Risk Cluster {cluster_id}"
    elif danger_score > 0.4:
        return f"Medium Risk Cluster {cluster_id}"
    else:
        return f"Low Risk Cluster {cluster_id}"


"""