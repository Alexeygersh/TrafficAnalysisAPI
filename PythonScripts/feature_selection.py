"""
PythonScripts/feature_selection.py  (v2)

Feature selection через silhouette score.

Отличия от v1:
  - Клипаем выбросы по 1-99 перцентилю ПЕРЕД K-Means.
    Без этого одна точка-выброс создаёт ложный "кластер" с силуэтом ~ 1.0.
  - Проверяем баланс кластеров: если один кластер < 5% точек - силуэт невалиден.
  - Дополнительно возвращаем проверочную метрику clusterBalance.

Публичная функция: rank_features(json_data, top_k=10)
"""

import json
import base64
from io import BytesIO

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler


NUMERIC_FEATURES = [
    'FlowDuration', 'TotalFwdPackets', 'TotalBackwardPackets',
    'TotalLengthFwdPackets', 'TotalLengthBwdPackets',
    'FwdPacketLengthMax', 'FwdPacketLengthMin',
    'FwdPacketLengthMean', 'FwdPacketLengthStd',
    'BwdPacketLengthMax', 'BwdPacketLengthMin',
    'BwdPacketLengthMean', 'BwdPacketLengthStd',
    'FlowBytesPerSec', 'FlowPacketsPerSec',
    'FwdPacketsPerSec', 'BwdPacketsPerSec',
    'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin',
    'FwdIATTotal', 'FwdIATMean', 'FwdIATStd', 'FwdIATMax', 'FwdIATMin',
    'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 'BwdIATMax', 'BwdIATMin',
    'FwdPSHFlags', 'BwdPSHFlags', 'FwdURGFlags', 'BwdURGFlags',
    'FINFlagCount', 'SYNFlagCount', 'RSTFlagCount', 'PSHFlagCount',
    'ACKFlagCount', 'URGFlagCount', 'CWEFlagCount', 'ECEFlagCount',
    'FwdHeaderLength', 'BwdHeaderLength', 'MinSegSizeForward',
    'MinPacketLength', 'MaxPacketLength', 'PacketLengthMean',
    'PacketLengthStd', 'PacketLengthVariance',
    'AveragePacketSize', 'AvgFwdSegmentSize', 'AvgBwdSegmentSize',
    'DownUpRatio',
    'InitWinBytesForward', 'InitWinBytesBackward', 'ActDataPktFwd',
    'SubflowFwdPackets', 'SubflowFwdBytes',
    'SubflowBwdPackets', 'SubflowBwdBytes',
    'ActiveMean', 'ActiveStd', 'ActiveMax', 'ActiveMin',
    'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin',
]


MIN_SAMPLES = 30
MIN_CLUSTER_RATIO = 0.05
CLIP_LOW = 1
CLIP_HIGH = 99


def _get(d, *keys, default=0.0):
    for k in keys:
        if k in d and d[k] is not None:
            try:
                return float(d[k])
            except (TypeError, ValueError):
                return default
    for k in keys:
        camel = k[0].lower() + k[1:]
        if camel in d and d[camel] is not None:
            try:
                return float(d[camel])
            except (TypeError, ValueError):
                return default
    return default


def _silhouette_for_feature(values):
    values = np.asarray(values, dtype=float).reshape(-1, 1)

    mask = np.isfinite(values).flatten()
    values = values[mask].reshape(-1, 1)

    if len(values) < MIN_SAMPLES:
        return {'score': None, 'balance': None,
                'note': f'not enough finite values ({len(values)})'}

    if np.std(values) == 0:
        return {'score': None, 'balance': None,
                'note': 'constant feature (std=0)'}

    # Клипаем выбросы
    p_low = np.percentile(values, CLIP_LOW)
    p_high = np.percentile(values, CLIP_HIGH)
    if p_low == p_high:
        return {'score': None, 'balance': None,
                'note': 'near-constant after outlier clip'}
    values_clipped = np.clip(values, p_low, p_high)

    try:
        scaler = StandardScaler()
        values_scaled = scaler.fit_transform(values_clipped)
    except Exception as e:
        return {'score': None, 'balance': None, 'note': f'scaling error: {e}'}

    try:
        km = KMeans(n_clusters=2, random_state=42, n_init=10)
        labels = km.fit_predict(values_scaled)
    except Exception as e:
        return {'score': None, 'balance': None, 'note': f'kmeans error: {e}'}

    unique, counts = np.unique(labels, return_counts=True)
    if len(unique) < 2:
        return {'score': None, 'balance': None, 'note': 'only one cluster formed'}

    balance = counts.min() / counts.sum()
    if balance < MIN_CLUSTER_RATIO:
        return {
            'score': None,
            'balance': float(balance),
            'note': f'unbalanced clusters ({counts.min()}/{counts.sum()})'
        }

    try:
        score = float(silhouette_score(values_scaled, labels))
    except Exception as e:
        return {'score': None, 'balance': float(balance),
                'note': f'silhouette error: {e}'}

    return {'score': score, 'balance': float(balance), 'note': ''}


def _build_chart(ranking, top_k=10):
    valid = [r for r in ranking if r['silhouette'] is not None]
    if not valid:
        return None

    valid.sort(key=lambda r: r['silhouette'], reverse=True)
    names = [r['feature'] for r in valid]
    scores = [r['silhouette'] for r in valid]
    colors = ['#2e7d32' if i < top_k else '#90a4ae' for i in range(len(valid))]

    fig_height = max(6, len(valid) * 0.3)
    fig, ax = plt.subplots(figsize=(10, fig_height))
    y_pos = np.arange(len(names))
    ax.barh(y_pos, scores, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel('Silhouette Score (outliers clipped, balanced check)',
                  fontsize=11)
    ax.set_title(f'Feature Ranking by Silhouette (top-{top_k} highlighted)',
                 fontsize=13, fontweight='bold')
    ax.axvline(x=0, color='red', linestyle='--', alpha=0.5, linewidth=1)
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=120, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode()
    plt.close()
    return f'data:image/png;base64,{image_base64}'


def rank_features(json_data, top_k=10):
    try:
        top_k = int(top_k)
    except Exception:
        top_k = 10

    flows = json.loads(json_data) if isinstance(json_data, str) else json_data
    n = len(flows)
    print(f"[feature_selection v2] Received {n} flows")

    if n < MIN_SAMPLES:
        return json.dumps({
            'error': f'Not enough samples: got {n}, need at least {MIN_SAMPLES}'
        })

    ranking = []
    for feat in NUMERIC_FEATURES:
        values = [_get(flow, feat) for flow in flows]
        r = _silhouette_for_feature(values)
        ranking.append({
            'feature': feat,
            'silhouette': None if r['score'] is None else round(r['score'], 4),
            'clusterBalance': None if r['balance'] is None else round(r['balance'], 4),
            'note': r['note'],
        })

    def sort_key(r):
        s = r['silhouette']
        if s is None:
            return (1, 0)
        return (0, -s)

    ranking.sort(key=sort_key)
    for i, r in enumerate(ranking, start=1):
        r['rank'] = i

    top_names = [r['feature'] for r in ranking
                 if r['silhouette'] is not None][:top_k]

    chart = _build_chart(ranking, top_k=top_k)

    result = {
        'totalSamples': n,
        'totalFeatures': len(NUMERIC_FEATURES),
        'validFeatures': sum(1 for r in ranking if r['silhouette'] is not None),
        'ranking': ranking,
        'top10': top_names,
        'chart': chart,
    }
    print(f"[feature_selection v2] Top-{top_k}: {top_names}")
    return json.dumps(result)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            data = f.read()
        result_json = rank_features(data, top_k=10)
        result = json.loads(result_json)
        print(f"\n=== RESULTS ===")
        if 'error' in result:
            print(f"ERROR: {result['error']}")
        else:
            print(f"Total samples:    {result['totalSamples']}")
            print(f"Total features:   {result['totalFeatures']}")
            print(f"Valid features:   {result['validFeatures']}")
            print(f"\nTop-10:")
            for i, name in enumerate(result['top10'], 1):
                r = next(r for r in result['ranking'] if r['feature'] == name)
                print(f"  {i:2d}. {name:30s}  silhouette = {r['silhouette']:.4f}"
                      f"  balance = {r['clusterBalance']:.2%}")
