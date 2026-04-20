"""
PythonScripts/cicids_mapping.py

Словарь соответствия между именами колонок в CICIDS-2017 CSV
и PascalCase-именами в FlowMetrics / feature_selection.

CICIDS имеет:
  - Ведущие пробелы в некоторых именах (" Destination Port")
  - Пробелы внутри (" Flow Duration")
  - Специальные символы (Flow Bytes/s, Down/Up Ratio)
  - Дубликаты (Fwd Header Length встречается дважды)
"""

# Маппинг: cicids_name (после strip) -> наш_name
# Используется после .strip() от имён колонок из CSV.
CICIDS_TO_CAMEL = {
    # Идентификация
    'Destination Port':            'DestinationPort',

    # Базовые
    'Flow Duration':               'FlowDuration',
    'Total Fwd Packets':           'TotalFwdPackets',
    'Total Backward Packets':      'TotalBackwardPackets',
    'Total Length of Fwd Packets': 'TotalLengthFwdPackets',
    'Total Length of Bwd Packets': 'TotalLengthBwdPackets',

    # Длины fwd/bwd
    'Fwd Packet Length Max':       'FwdPacketLengthMax',
    'Fwd Packet Length Min':       'FwdPacketLengthMin',
    'Fwd Packet Length Mean':      'FwdPacketLengthMean',
    'Fwd Packet Length Std':       'FwdPacketLengthStd',
    'Bwd Packet Length Max':       'BwdPacketLengthMax',
    'Bwd Packet Length Min':       'BwdPacketLengthMin',
    'Bwd Packet Length Mean':      'BwdPacketLengthMean',
    'Bwd Packet Length Std':       'BwdPacketLengthStd',

    # Скорости
    'Flow Bytes/s':                'FlowBytesPerSec',
    'Flow Packets/s':              'FlowPacketsPerSec',
    'Fwd Packets/s':               'FwdPacketsPerSec',
    'Bwd Packets/s':               'BwdPacketsPerSec',

    # IAT
    'Flow IAT Mean':               'FlowIATMean',
    'Flow IAT Std':                'FlowIATStd',
    'Flow IAT Max':                'FlowIATMax',
    'Flow IAT Min':                'FlowIATMin',
    'Fwd IAT Total':               'FwdIATTotal',
    'Fwd IAT Mean':                'FwdIATMean',
    'Fwd IAT Std':                 'FwdIATStd',
    'Fwd IAT Max':                 'FwdIATMax',
    'Fwd IAT Min':                 'FwdIATMin',
    'Bwd IAT Total':               'BwdIATTotal',
    'Bwd IAT Mean':                'BwdIATMean',
    'Bwd IAT Std':                 'BwdIATStd',
    'Bwd IAT Max':                 'BwdIATMax',
    'Bwd IAT Min':                 'BwdIATMin',

    # Флаги
    'Fwd PSH Flags':               'FwdPSHFlags',
    'Bwd PSH Flags':               'BwdPSHFlags',
    'Fwd URG Flags':               'FwdURGFlags',
    'Bwd URG Flags':               'BwdURGFlags',
    'FIN Flag Count':              'FINFlagCount',
    'SYN Flag Count':              'SYNFlagCount',
    'RST Flag Count':              'RSTFlagCount',
    'PSH Flag Count':              'PSHFlagCount',
    'ACK Flag Count':              'ACKFlagCount',
    'URG Flag Count':              'URGFlagCount',
    'CWE Flag Count':              'CWEFlagCount',
    'ECE Flag Count':              'ECEFlagCount',

    # Headers (дубликат 'Fwd Header Length' обрабатывается отдельно)
    'Fwd Header Length':           'FwdHeaderLength',
    'Bwd Header Length':           'BwdHeaderLength',
    'min_seg_size_forward':        'MinSegSizeForward',

    # Packet length aggregates
    'Min Packet Length':           'MinPacketLength',
    'Max Packet Length':           'MaxPacketLength',
    'Packet Length Mean':          'PacketLengthMean',
    'Packet Length Std':           'PacketLengthStd',
    'Packet Length Variance':      'PacketLengthVariance',

    # Средние
    'Average Packet Size':         'AveragePacketSize',
    'Avg Fwd Segment Size':        'AvgFwdSegmentSize',
    'Avg Bwd Segment Size':        'AvgBwdSegmentSize',
    'Down/Up Ratio':               'DownUpRatio',

    # Init win
    'Init_Win_bytes_forward':      'InitWinBytesForward',
    'Init_Win_bytes_backward':     'InitWinBytesBackward',
    'act_data_pkt_fwd':            'ActDataPktFwd',

    # Bulk
    'Fwd Avg Bytes/Bulk':          'FwdAvgBytesBulk',
    'Fwd Avg Packets/Bulk':        'FwdAvgPacketsBulk',
    'Fwd Avg Bulk Rate':           'FwdAvgBulkRate',
    'Bwd Avg Bytes/Bulk':          'BwdAvgBytesBulk',
    'Bwd Avg Packets/Bulk':        'BwdAvgPacketsBulk',
    'Bwd Avg Bulk Rate':           'BwdAvgBulkRate',

    # Subflow
    'Subflow Fwd Packets':         'SubflowFwdPackets',
    'Subflow Fwd Bytes':           'SubflowFwdBytes',
    'Subflow Bwd Packets':         'SubflowBwdPackets',
    'Subflow Bwd Bytes':           'SubflowBwdBytes',

    # Active / Idle
    'Active Mean':                 'ActiveMean',
    'Active Std':                  'ActiveStd',
    'Active Max':                  'ActiveMax',
    'Active Min':                  'ActiveMin',
    'Idle Mean':                   'IdleMean',
    'Idle Std':                    'IdleStd',
    'Idle Max':                    'IdleMax',
    'Idle Min':                    'IdleMin',

    # Метка
    'Label':                       'Label',
}


def normalize_cicids_columns(df):
    """
    Приводит df со столбцами CICIDS к нашим PascalCase-именам.
    Убирает пробелы и переименовывает по словарю.
    Дубликат 'Fwd Header Length' — убираем второе вхождение.
    """
    # Очищаем от пробелов
    df.columns = [c.strip() for c in df.columns]

    # Убираем дубликаты имён (второе вхождение 'Fwd Header Length')
    seen = set()
    keep = []
    for i, col in enumerate(df.columns):
        if col in seen:
            continue
        seen.add(col)
        keep.append(i)
    df = df.iloc[:, keep]

    # Переименовываем
    rename_map = {old: new for old, new in CICIDS_TO_CAMEL.items()
                  if old in df.columns}
    df = df.rename(columns=rename_map)
    return df
