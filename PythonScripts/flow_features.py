"""
PythonScripts/flow_features.py

Группирует сырые пакеты из .pcap в двунаправленные flows (CICFlowMeter-style)
и считает все признаки из твоего списка "все_признаки.txt".

Входные данные: JSON-строка со списком объектов RawPacket (из PcapParserService.cs).
Выходные данные: JSON-строка со списком flow-объектов, каждый с ~78 признаками.

Логика flow:
  - Ключ flow = (minIP, maxIP, minPort, maxPort, protocol) — канонизированный,
    чтобы A→B и B→A попадали в один flow.
  - Первый пакет задаёт направление forward: кто отправитель = src_fwd.
  - Следующие пакеты: если srcIP==src_fwd → forward, иначе backward.
  - FLOW_TIMEOUT = 120 сек. После паузы > 120 сек начинается новый flow.
  - ACTIVITY_TIMEOUT = 5 сек. Паузы > 5 сек внутри flow = idle период.
"""

import json
import numpy as np
from collections import defaultdict


FLOW_TIMEOUT = 120.0       # сек — после этой паузы начинается НОВЫЙ flow
ACTIVITY_TIMEOUT = 5.0     # сек — граница между active и idle периодом


def _get(d, *keys, default=0):
    """Читаем поля в любом case (PascalCase / camelCase)."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _canonical_key(p):
    """
    Канонизированный ключ flow: чтобы A→B и B→A попадали в один flow.
    Сортируем (IP,port) лексикографически.
    """
    src_ip = _get(p, 'SourceIP', 'sourceIP', default='')
    dst_ip = _get(p, 'DestinationIP', 'destinationIP', default='')
    src_port = int(_get(p, 'SourcePort', 'sourcePort', default=0))
    dst_port = int(_get(p, 'DestinationPort', 'destinationPort', default=0))
    proto = _get(p, 'Protocol', 'protocol', default='')

    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a[0], b[0], a[1], b[1], proto)
    else:
        return (b[0], a[0], b[1], a[1], proto)


def _safe_stats(arr):
    """Возвращает (min, max, mean, std) для списка. Нули если пусто."""
    if not arr:
        return 0.0, 0.0, 0.0, 0.0
    a = np.asarray(arr, dtype=float)
    return float(a.min()), float(a.max()), float(a.mean()), float(a.std())


def _compute_active_idle(timestamps):
    """
    Для упорядоченного списка таймстампов пакетов внутри flow
    разделяет время на active (паузы < ACTIVITY_TIMEOUT) и idle (паузы >= ACTIVITY_TIMEOUT).

    Возвращает списки длительностей active и idle периодов в секундах.
    """
    if len(timestamps) < 2:
        return [], []

    ts = sorted(timestamps)
    active_periods = []
    idle_periods = []

    period_start = ts[0]
    last = ts[0]

    for t in ts[1:]:
        gap = t - last
        if gap >= ACTIVITY_TIMEOUT:
            # Закрываем текущий active-период
            active_periods.append(last - period_start)
            idle_periods.append(gap)
            period_start = t
        last = t

    # Закрываем последний active-период
    active_periods.append(last - period_start)

    # Отфильтровываем нулевые active-периоды (когда пакет одиночный в сегменте)
    active_periods = [a for a in active_periods if a > 0]

    return active_periods, idle_periods


def _split_into_flows(packets):
    """
    Разбивает пакеты на flows с учётом FLOW_TIMEOUT.
    Возвращает dict: flow_id -> list of packets (в хронологическом порядке).
    Flow_id это tuple (canonical_key, chunk_index).
    """
    # Сортируем всё по времени
    packets_sorted = sorted(
        packets,
        key=lambda p: float(_get(p, 'TimestampSec', 'timestampSec', default=0.0))
    )

    flows = defaultdict(list)
    # last_time_for_key: когда последний раз видели пакет с таким ключом
    last_time_for_key = {}
    # chunk_index_for_key: сколько уже flows было с таким ключом (для timeout'а)
    chunk_idx_for_key = {}

    for p in packets_sorted:
        key = _canonical_key(p)
        t = float(_get(p, 'TimestampSec', 'timestampSec', default=0.0))

        if key in last_time_for_key:
            if t - last_time_for_key[key] > FLOW_TIMEOUT:
                # timeout → новый flow
                chunk_idx_for_key[key] = chunk_idx_for_key.get(key, 0) + 1
        else:
            chunk_idx_for_key[key] = 0

        flow_id = (key, chunk_idx_for_key[key])
        flows[flow_id].append(p)
        last_time_for_key[key] = t

    return flows


def _build_flow_features(flow_id, flow_packets):
    """Строит полный набор признаков для одного flow."""
    # Определяем forward-направление по первому пакету
    first = flow_packets[0]
    fwd_src_ip = _get(first, 'SourceIP', 'sourceIP', default='')
    fwd_dst_ip = _get(first, 'DestinationIP', 'destinationIP', default='')
    fwd_src_port = int(_get(first, 'SourcePort', 'sourcePort', default=0))
    fwd_dst_port = int(_get(first, 'DestinationPort', 'destinationPort', default=0))
    protocol = _get(first, 'Protocol', 'protocol', default='')

    # Разделяем на fwd и bwd
    fwd_packets = []
    bwd_packets = []
    for p in flow_packets:
        src = _get(p, 'SourceIP', 'sourceIP', default='')
        if src == fwd_src_ip:
            fwd_packets.append(p)
        else:
            bwd_packets.append(p)

    # --- Таймстампы ---
    all_ts = sorted(float(_get(p, 'TimestampSec', 'timestampSec', default=0.0))
                    for p in flow_packets)
    fwd_ts = sorted(float(_get(p, 'TimestampSec', 'timestampSec', default=0.0))
                    for p in fwd_packets)
    bwd_ts = sorted(float(_get(p, 'TimestampSec', 'timestampSec', default=0.0))
                    for p in bwd_packets)

    flow_start = all_ts[0]
    flow_end = all_ts[-1]
    flow_duration_sec = flow_end - flow_start
    flow_duration_us = flow_duration_sec * 1_000_000  # в микросекундах (CICFlowMeter-style)

    # --- Длины пакетов ---
    fwd_lens = [int(_get(p, 'PacketSize', 'packetSize', default=0)) for p in fwd_packets]
    bwd_lens = [int(_get(p, 'PacketSize', 'packetSize', default=0)) for p in bwd_packets]
    all_lens = fwd_lens + bwd_lens

    # --- IAT (Inter-Arrival Time) ---
    def iat_list(ts):
        return [ts[i+1] - ts[i] for i in range(len(ts) - 1)] if len(ts) > 1 else []

    flow_iat = iat_list(all_ts)
    fwd_iat = iat_list(fwd_ts)
    bwd_iat = iat_list(bwd_ts)

    # --- TCP Flags ---
    def flag_count(packets, flag_name_pascal, flag_name_camel):
        return sum(1 for p in packets if _get(p, flag_name_pascal, flag_name_camel, default=False))

    fwd_psh = flag_count(fwd_packets, 'FlagPSH', 'flagPSH')
    bwd_psh = flag_count(bwd_packets, 'FlagPSH', 'flagPSH')
    fwd_urg = flag_count(fwd_packets, 'FlagURG', 'flagURG')
    bwd_urg = flag_count(bwd_packets, 'FlagURG', 'flagURG')

    fin_count = flag_count(flow_packets, 'FlagFIN', 'flagFIN')
    syn_count = flag_count(flow_packets, 'FlagSYN', 'flagSYN')
    rst_count = flag_count(flow_packets, 'FlagRST', 'flagRST')
    psh_count = flag_count(flow_packets, 'FlagPSH', 'flagPSH')
    ack_count = flag_count(flow_packets, 'FlagACK', 'flagACK')
    urg_count = flag_count(flow_packets, 'FlagURG', 'flagURG')
    ece_count = flag_count(flow_packets, 'FlagECE', 'flagECE')
    cwe_count = flag_count(flow_packets, 'FlagCWR', 'flagCWR')

    # --- Headers ---
    fwd_header_lens = [int(_get(p, 'HeaderLength', 'headerLength', default=0)) for p in fwd_packets]
    bwd_header_lens = [int(_get(p, 'HeaderLength', 'headerLength', default=0)) for p in bwd_packets]

    fwd_header_total = sum(fwd_header_lens)
    bwd_header_total = sum(bwd_header_lens)
    min_seg_size_fwd = min(fwd_header_lens) if fwd_header_lens else 0

    # --- Init Window (TCP) ---
    init_win_fwd = int(_get(fwd_packets[0], 'WindowSize', 'windowSize', default=0)) if fwd_packets else 0
    init_win_bwd = int(_get(bwd_packets[0], 'WindowSize', 'windowSize', default=0)) if bwd_packets else 0

    # --- Payload packets (fwd) ---
    act_data_pkt_fwd = sum(
        1 for p in fwd_packets
        if int(_get(p, 'PayloadSize', 'payloadSize', default=0)) > 0
    )

    # --- Active / Idle периоды ---
    active_periods, idle_periods = _compute_active_idle(all_ts)
    active_min, active_max, active_mean, active_std = _safe_stats(active_periods)
    idle_min, idle_max, idle_mean, idle_std = _safe_stats(idle_periods)

    # --- Статистики длин пакетов ---
    fwd_len_min, fwd_len_max, fwd_len_mean, fwd_len_std = _safe_stats(fwd_lens)
    bwd_len_min, bwd_len_max, bwd_len_mean, bwd_len_std = _safe_stats(bwd_lens)
    pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std = _safe_stats(all_lens)
    pkt_len_var = pkt_len_std ** 2

    # --- Статистики IAT ---
    flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std = _safe_stats(flow_iat)
    # Конвертим в микросекунды
    flow_iat_min *= 1_000_000
    flow_iat_max *= 1_000_000
    flow_iat_mean *= 1_000_000
    flow_iat_std *= 1_000_000

    fwd_iat_total = sum(fwd_iat)
    fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std = _safe_stats(fwd_iat)
    fwd_iat_total *= 1_000_000
    fwd_iat_min *= 1_000_000
    fwd_iat_max *= 1_000_000
    fwd_iat_mean *= 1_000_000
    fwd_iat_std *= 1_000_000

    bwd_iat_total = sum(bwd_iat)
    bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std = _safe_stats(bwd_iat)
    bwd_iat_total *= 1_000_000
    bwd_iat_min *= 1_000_000
    bwd_iat_max *= 1_000_000
    bwd_iat_mean *= 1_000_000
    bwd_iat_std *= 1_000_000

    # --- Скорости ---
    total_bytes = sum(all_lens)
    n_packets = len(flow_packets)

    flow_bytes_per_sec = (total_bytes / flow_duration_sec) if flow_duration_sec > 0 else 0.0
    flow_packets_per_sec = (n_packets / flow_duration_sec) if flow_duration_sec > 0 else 0.0
    fwd_packets_per_sec = (len(fwd_packets) / flow_duration_sec) if flow_duration_sec > 0 else 0.0
    bwd_packets_per_sec = (len(bwd_packets) / flow_duration_sec) if flow_duration_sec > 0 else 0.0

    # --- Средние размеры сегментов ---
    avg_fwd_seg_size = fwd_len_mean
    avg_bwd_seg_size = bwd_len_mean
    avg_packet_size = pkt_len_mean

    # --- Down/Up ratio ---
    down_up_ratio = (len(bwd_packets) / len(fwd_packets)) if len(fwd_packets) > 0 else 0.0

    # --- Bulk — упрощённо. "Bulk" по CICFlowMeter — это >=4 пакетов подряд в одном
    #     направлении с паузами <1 сек и суммарным payload >0. Для простоты считаем 0.
    #     TODO: полноценная реализация, если окажется что эти признаки важны.
    fwd_avg_bytes_bulk = 0.0
    fwd_avg_packets_bulk = 0.0
    fwd_avg_bulk_rate = 0.0
    bwd_avg_bytes_bulk = 0.0
    bwd_avg_packets_bulk = 0.0
    bwd_avg_bulk_rate = 0.0

    # --- Subflow — в CICFlowMeter это разбиение на части по паузам.
    #     В простом случае subflow = целый flow.
    subflow_fwd_packets = len(fwd_packets)
    subflow_fwd_bytes = sum(fwd_lens)
    subflow_bwd_packets = len(bwd_packets)
    subflow_bwd_bytes = sum(bwd_lens)

    # ===========================================================
    # Итоговый dict со всеми признаками (имена — как в ТЗ)
    # ===========================================================
    return {
        # Идентификация flow
        'SourceIP': fwd_src_ip,
        'DestinationIP': fwd_dst_ip,
        'SourcePort': fwd_src_port,
        'DestinationPort': fwd_dst_port,
        'Protocol': protocol,
        'FlowStartTime': flow_start,
        'FlowEndTime': flow_end,

        # Базовые
        'FlowDuration': flow_duration_us,
        'TotalFwdPackets': len(fwd_packets),
        'TotalBackwardPackets': len(bwd_packets),
        'TotalLengthFwdPackets': sum(fwd_lens),
        'TotalLengthBwdPackets': sum(bwd_lens),

        # Длины пакетов (fwd/bwd)
        'FwdPacketLengthMax': fwd_len_max,
        'FwdPacketLengthMin': fwd_len_min,
        'FwdPacketLengthMean': fwd_len_mean,
        'FwdPacketLengthStd': fwd_len_std,
        'BwdPacketLengthMax': bwd_len_max,
        'BwdPacketLengthMin': bwd_len_min,
        'BwdPacketLengthMean': bwd_len_mean,
        'BwdPacketLengthStd': bwd_len_std,

        # Скорости
        'FlowBytesPerSec': flow_bytes_per_sec,
        'FlowPacketsPerSec': flow_packets_per_sec,
        'FwdPacketsPerSec': fwd_packets_per_sec,
        'BwdPacketsPerSec': bwd_packets_per_sec,

        # IAT
        'FlowIATMean': flow_iat_mean,
        'FlowIATStd': flow_iat_std,
        'FlowIATMax': flow_iat_max,
        'FlowIATMin': flow_iat_min,
        'FwdIATTotal': fwd_iat_total,
        'FwdIATMean': fwd_iat_mean,
        'FwdIATStd': fwd_iat_std,
        'FwdIATMax': fwd_iat_max,
        'FwdIATMin': fwd_iat_min,
        'BwdIATTotal': bwd_iat_total,
        'BwdIATMean': bwd_iat_mean,
        'BwdIATStd': bwd_iat_std,
        'BwdIATMax': bwd_iat_max,
        'BwdIATMin': bwd_iat_min,

        # TCP Flags
        'FwdPSHFlags': fwd_psh,
        'BwdPSHFlags': bwd_psh,
        'FwdURGFlags': fwd_urg,
        'BwdURGFlags': bwd_urg,
        'FINFlagCount': fin_count,
        'SYNFlagCount': syn_count,
        'RSTFlagCount': rst_count,
        'PSHFlagCount': psh_count,
        'ACKFlagCount': ack_count,
        'URGFlagCount': urg_count,
        'CWEFlagCount': cwe_count,
        'ECEFlagCount': ece_count,

        # Headers
        'FwdHeaderLength': fwd_header_total,
        'BwdHeaderLength': bwd_header_total,
        'MinSegSizeForward': min_seg_size_fwd,

        # Packet length aggregates
        'MinPacketLength': pkt_len_min,
        'MaxPacketLength': pkt_len_max,
        'PacketLengthMean': pkt_len_mean,
        'PacketLengthStd': pkt_len_std,
        'PacketLengthVariance': pkt_len_var,

        # Средние размеры
        'AveragePacketSize': avg_packet_size,
        'AvgFwdSegmentSize': avg_fwd_seg_size,
        'AvgBwdSegmentSize': avg_bwd_seg_size,
        'DownUpRatio': down_up_ratio,

        # Init Window + payload pkts
        'InitWinBytesForward': init_win_fwd,
        'InitWinBytesBackward': init_win_bwd,
        'ActDataPktFwd': act_data_pkt_fwd,

        # Bulk (упрощённо)
        'FwdAvgBytesBulk': fwd_avg_bytes_bulk,
        'FwdAvgPacketsBulk': fwd_avg_packets_bulk,
        'FwdAvgBulkRate': fwd_avg_bulk_rate,
        'BwdAvgBytesBulk': bwd_avg_bytes_bulk,
        'BwdAvgPacketsBulk': bwd_avg_packets_bulk,
        'BwdAvgBulkRate': bwd_avg_bulk_rate,

        # Subflow
        'SubflowFwdPackets': subflow_fwd_packets,
        'SubflowFwdBytes': subflow_fwd_bytes,
        'SubflowBwdPackets': subflow_bwd_packets,
        'SubflowBwdBytes': subflow_bwd_bytes,

        # Active / Idle
        'ActiveMean': active_mean * 1_000_000,
        'ActiveStd': active_std * 1_000_000,
        'ActiveMax': active_max * 1_000_000,
        'ActiveMin': active_min * 1_000_000,
        'IdleMean': idle_mean * 1_000_000,
        'IdleStd': idle_std * 1_000_000,
        'IdleMax': idle_max * 1_000_000,
        'IdleMin': idle_min * 1_000_000,
    }


# =============================================================
# ПУБЛИЧНАЯ ФУНКЦИЯ — её будет вызывать C#
# =============================================================
def build_flows_from_packets(json_data):
    """
    Принимает JSON-строку: список RawPacket.
    Возвращает JSON-строку: список flow-объектов со всеми признаками.
    """
    packets = json.loads(json_data)
    print(f"[flow_features] Received {len(packets)} raw packets")

    if len(packets) == 0:
        return json.dumps([])

    flows_dict = _split_into_flows(packets)
    print(f"[flow_features] Grouped into {len(flows_dict)} flows")

    result = []
    for flow_id, flow_packets in flows_dict.items():
        try:
            features = _build_flow_features(flow_id, flow_packets)
            result.append(features)
        except Exception as e:
            print(f"[flow_features] Skipped flow {flow_id}: {e}")

    print(f"[flow_features] Built features for {len(result)} flows")
    return json.dumps(result, default=str)


# =============================================================
# Локальное тестирование из командной строки
# python flow_features.py test_packets.json
# =============================================================
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            data = f.read()
        out = build_flows_from_packets(data)
        flows = json.loads(out)
        print(f"\n=== RESULTS ===")
        print(f"Total flows: {len(flows)}")
        if flows:
            print(f"\nFirst flow example:")
            for k, v in flows[0].items():
                print(f"  {k}: {v}")