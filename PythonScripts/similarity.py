"""
similarity.py
=============
Расчёт меры сходства между сетевыми потоками (flows).

Формула из ТЗ диплома:
    Sim = w1·Sim_port + w2·Sim_num + w3·Sim_bin

Блоки:
    A (port/addr) — точное совпадение IP/портов/протокола
    B (numeric)   — Z-score нормализация + евклидово расстояние → exp(-d)
    C (binary)    — Simple Matching Coefficient по бинарным TCP-флагам

Два режима:
    1. find_similar_flows() — top-K похожих на target (быстро, циклом)
    2. knn_classify_flows() — kNN-классификация всех flows
       Использует векторизацию NumPy: вся sim-матрица вычисляется
       за O(n²) numpy-операций вместо Python-циклов. Ускорение ~30x.
"""

import json
import math
import numpy as np


# ============================================================
# Какие поля попадают в каждый блок
# ============================================================

BLOCK_A_FIELDS = [
    'SourceIP',
    'DestinationIP',
    'SourcePort',
    'DestinationPort',
    'Protocol',
]

BLOCK_C_FIELDS = [
    'FINFlagCount',
    'SYNFlagCount',
    'RSTFlagCount',
    'PSHFlagCount',
    'ACKFlagCount',
    'URGFlagCount',
    'CWEFlagCount',
    'ECEFlagCount',
]

EXCLUDED_NUMERIC = {
    'Id', 'SessionId', 'FlowId',
    'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'Protocol',
    'FlowStartTime', 'FlowEndTime',
    'IsAttack', 'Confidence', 'ThreatLevel',
}


# ============================================================
# РЕЖИМ 1: find_similar_flows
# ============================================================

def find_similar_flows(flows_json, target_flow_id, w1, w2, w3, k=10):
    flows = json.loads(flows_json)
    if not flows:
        return json.dumps({"error": "Empty flows list", "results": []})

    w1, w2, w3 = _normalize_weights(w1, w2, w3)

    target = next((f for f in flows if f.get('Id') == target_flow_id), None)
    if target is None:
        return json.dumps({
            "error": f"Target flow with id={target_flow_id} not found",
            "results": []
        })

    numeric_fields = _detect_numeric_fields(flows)
    norm_data = _zscore_normalize(flows, numeric_fields)
    target_idx = next(i for i, f in enumerate(flows) if f.get('Id') == target_flow_id)
    target_norm = norm_data[target_idx]

    results = []
    for i, flow in enumerate(flows):
        if flow.get('Id') == target_flow_id:
            continue
        sim_a = _block_a_similarity(target, flow)
        sim_b = _block_b_similarity_single(target_norm, norm_data[i])
        sim_c = _block_c_similarity(target, flow)
        sim = w1 * sim_a + w2 * sim_b + w3 * sim_c

        results.append({
            "flowId": flow.get('Id'),
            "sourceIP": flow.get('SourceIP', ''),
            "destinationIP": flow.get('DestinationIP', ''),
            "sourcePort": flow.get('SourcePort', 0),
            "destinationPort": flow.get('DestinationPort', 0),
            "protocol": flow.get('Protocol', ''),
            "isAttack": bool(flow.get('IsAttack', False)),
            "threatLevel": flow.get('ThreatLevel', 'Low'),
            "simA": round(sim_a, 4),
            "simB": round(sim_b, 4),
            "simC": round(sim_c, 4),
            "sim": round(sim, 4),
        })

    results.sort(key=lambda r: r['sim'], reverse=True)
    results = results[:k]

    return json.dumps({
        "targetFlow": _flow_summary(target),
        "weights": {"w1": round(w1, 4), "w2": round(w2, 4), "w3": round(w3, 4)},
        "blocks": {
            "A": BLOCK_A_FIELDS,
            "B": numeric_fields,
            "C": BLOCK_C_FIELDS,
        },
        "totalCandidates": len(flows) - 1,
        "k": k,
        "results": results,
    })


# ============================================================
# РЕЖИМ 2: knn_classify_flows (ВЕКТОРИЗОВАННАЯ ВЕРСИЯ)
# ============================================================

def knn_classify_flows(flows_json, labels_json, w1, w2, w3, k=5):
    """
    kNN-классификатор на мере сходства.
    Все попарные sim считаются векторизованно через numpy за O(n²)
    matrix-операций вместо Python-циклов. Ускорение ~30x.
    """
    flows = json.loads(flows_json)
    labels = json.loads(labels_json)

    if not flows or len(flows) < k + 1:
        return json.dumps({
            "error": f"Need at least {k+1} flows, got {len(flows) if flows else 0}",
            "predictions": []
        })

    w1, w2, w3 = _normalize_weights(w1, w2, w3)
    n = len(flows)

    # ============================================================
    # ШАГ 1: ПОДГОТОВКА МАТРИЦ
    # ============================================================

    # Блок B — числовые признаки, Z-score нормализованные
    numeric_fields = _detect_numeric_fields(flows)
    B = _zscore_normalize(flows, numeric_fields)   # (n, m_b)

    # Блок A — категориальные. Конвертируем в строки → числа через факторизацию
    # (для каждой колонки своё мэппинг str→int)
    A_str = np.array([
        [str(f.get(field, '')) for field in BLOCK_A_FIELDS]
        for f in flows
    ])  # (n, 5)

    # Блок C — бинаризованные флаги
    C = np.zeros((n, len(BLOCK_C_FIELDS)), dtype=np.int8)
    for i, f in enumerate(flows):
        for j, field in enumerate(BLOCK_C_FIELDS):
            C[i, j] = 1 if (f.get(field, 0) or 0) > 0 else 0

    # ============================================================
    # ШАГ 2: ВЕКТОРИЗАЦИЯ — ВСЕ ПОПАРНЫЕ SIM СРАЗУ
    # ============================================================

    # --- Sim_A: матрица (n, n) долей совпадения по A-полям ---
    # Для каждой A-колонки получаем (n,n) матрицу совпадений и усредняем
    sim_a_matrix = np.zeros((n, n), dtype=np.float64)
    for col_idx in range(len(BLOCK_A_FIELDS)):
        col = A_str[:, col_idx]
        # equals[i,j] = (col[i] == col[j])
        equals = (col[:, None] == col[None, :]).astype(np.float64)
        sim_a_matrix += equals
    sim_a_matrix /= len(BLOCK_A_FIELDS)

    # --- Sim_B: матрица (n, n) — exp(-d / sqrt(m_b)) ---
    # Через сумму квадратов разностей: ||a-b||² = ||a||² + ||b||² - 2·a·b
    if B.shape[1] > 0:
        sq_norms = (B * B).sum(axis=1)            # (n,)
        dot = B @ B.T                              # (n, n)
        dist_sq = sq_norms[:, None] + sq_norms[None, :] - 2 * dot
        dist_sq = np.maximum(dist_sq, 0)           # численная защита
        dist = np.sqrt(dist_sq)
        scale = math.sqrt(B.shape[1])
        sim_b_matrix = np.exp(-dist / scale)
    else:
        sim_b_matrix = np.zeros((n, n), dtype=np.float64)

    # --- Sim_C: SMC через AND/XOR на бинарной матрице ---
    # SMC = (matches) / total. matches = total - hamming_distance
    m_c = C.shape[1]
    if m_c > 0:
        # Для каждой пары: число совпадающих бит
        # XOR: 1 если разные, 0 если одинаковые. Сумма по фичам = #разных
        # m_c - #разных = #одинаковых
        # Используем: matches = m_c - hamming
        # hamming(i,j) = sum over k of |C[i,k] - C[j,k]| (для бинарных = XOR)
        # Вычислим через C·C.T для одинаковых единиц + (1-C)·(1-C).T для одинаковых нулей
        ones_match = C @ C.T                                    # (n,n) — оба = 1
        zeros_match = (1 - C) @ (1 - C).T                       # оба = 0
        sim_c_matrix = (ones_match + zeros_match).astype(np.float64) / m_c
    else:
        sim_c_matrix = np.zeros((n, n), dtype=np.float64)

    # --- Итоговая sim-матрица ---
    sim_matrix = w1 * sim_a_matrix + w2 * sim_b_matrix + w3 * sim_c_matrix

    # На диагонали обнуляем (сам с собой не сравниваем)
    np.fill_diagonal(sim_matrix, -1)  # -1 чтобы не попасть в top-k

    # ============================================================
    # ШАГ 3: kNN — для каждой строки находим top-k по sim
    # ============================================================

    # labels: {str(id): bool}, приведём к {int: bool}
    labels_map = {int(k_): bool(v) for k_, v in labels.items()}
    flow_ids = [f.get('Id') for f in flows]
    labels_arr = np.array(
        [labels_map.get(fid, False) for fid in flow_ids],
        dtype=bool
    )

    # argsort по убыванию по каждой строке, берём первые k
    # (быстрее использовать argpartition + потом сортировать только k)
    if k < n:
        top_k_idx = np.argpartition(-sim_matrix, k, axis=1)[:, :k]
        # Эти k индексов не отсортированы — отсортируем по sim каждую строку
        for i in range(n):
            row_sims = sim_matrix[i, top_k_idx[i]]
            order = np.argsort(-row_sims)
            top_k_idx[i] = top_k_idx[i, order]
    else:
        top_k_idx = np.argsort(-sim_matrix, axis=1)[:, :k]

    # ============================================================
    # ШАГ 4: формируем результат
    # ============================================================

    predictions = []
    for i in range(n):
        target_id = flow_ids[i]
        flow_i = flows[i]

        neighbors = []
        for j_idx in top_k_idx[i]:
            neighbors.append({
                "flowId": flow_ids[j_idx],
                "sim": round(float(sim_matrix[i, j_idx]), 4),
                "isAttack": bool(labels_arr[j_idx])
            })

        attack_votes = sum(1 for n_ in neighbors if n_['isAttack'])
        knn_confidence = attack_votes / k if k > 0 else 0.0
        knn_is_attack = knn_confidence > 0.5

        predictions.append({
            "flowId": target_id,
            "sourceIP": flow_i.get('SourceIP', ''),
            "destinationIP": flow_i.get('DestinationIP', ''),
            "destinationPort": flow_i.get('DestinationPort', 0),
            "protocol": flow_i.get('Protocol', ''),
            "knnIsAttack": knn_is_attack,
            "knnConfidence": round(knn_confidence, 4),
            "neighbors": neighbors,
            "originalLabel": bool(labels_arr[i]),
        })

    knn_attacks = sum(1 for p in predictions if p['knnIsAttack'])
    original_attacks = int(labels_arr.sum())
    agree = sum(1 for p in predictions
                if p['knnIsAttack'] == p['originalLabel'])
    agreement = agree / n if n > 0 else 0.0

    return json.dumps({
        "totalFlows": n,
        "knnAttackFlows": knn_attacks,
        "originalAttackFlows": original_attacks,
        "agreementWithOriginal": round(agreement, 4),
        "weights": {"w1": round(w1, 4), "w2": round(w2, 4), "w3": round(w3, 4)},
        "k": k,
        "blocks": {
            "A": BLOCK_A_FIELDS,
            "B": numeric_fields,
            "C": BLOCK_C_FIELDS,
        },
        "predictions": predictions,
    })


# ============================================================
# Helpers
# ============================================================

def _normalize_weights(w1, w2, w3):
    total = w1 + w2 + w3
    if total <= 0:
        return 1/3, 1/3, 1/3
    return w1 / total, w2 / total, w3 / total


def _detect_numeric_fields(flows):
    if not flows:
        return []
    sample = flows[0]
    numeric = []
    for key, val in sample.items():
        if key in EXCLUDED_NUMERIC:
            continue
        if key in BLOCK_C_FIELDS:
            continue
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            numeric.append(key)
    return numeric


def _zscore_normalize(flows, numeric_fields):
    n = len(flows)
    m = len(numeric_fields)
    data = np.zeros((n, m), dtype=np.float64)

    for i, flow in enumerate(flows):
        for j, field in enumerate(numeric_fields):
            v = flow.get(field, 0)
            if v is None:
                v = 0
            try:
                data[i, j] = float(v)
            except (TypeError, ValueError):
                data[i, j] = 0.0

    data[~np.isfinite(data)] = 0.0
    means = data.mean(axis=0)
    stds = data.std(axis=0)
    stds[stds < 1e-9] = 1.0
    return (data - means) / stds


def _block_a_similarity(target, other):
    matches = 0
    total = len(BLOCK_A_FIELDS)
    for field in BLOCK_A_FIELDS:
        if str(target.get(field, '')) == str(other.get(field, '')):
            matches += 1
    return matches / total if total > 0 else 0.0


def _block_b_similarity_single(target_norm, other_norm):
    if len(target_norm) == 0:
        return 0.0
    diff = target_norm - other_norm
    d = np.sqrt(np.sum(diff * diff))
    d_scaled = d / math.sqrt(len(target_norm))
    return float(math.exp(-d_scaled))


def _block_c_similarity(target, other):
    matches = 0
    total = len(BLOCK_C_FIELDS)
    for field in BLOCK_C_FIELDS:
        t = 1 if (target.get(field, 0) or 0) > 0 else 0
        o = 1 if (other.get(field, 0) or 0) > 0 else 0
        if t == o:
            matches += 1
    return matches / total if total > 0 else 0.0


def _flow_summary(flow):
    return {
        "flowId": flow.get('Id'),
        "sourceIP": flow.get('SourceIP', ''),
        "destinationIP": flow.get('DestinationIP', ''),
        "sourcePort": flow.get('SourcePort', 0),
        "destinationPort": flow.get('DestinationPort', 0),
        "protocol": flow.get('Protocol', ''),
        "isAttack": bool(flow.get('IsAttack', False)),
        "threatLevel": flow.get('ThreatLevel', 'Low'),
    }
