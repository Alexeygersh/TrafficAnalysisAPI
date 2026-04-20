using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
    /// <summary>
    /// Агрегированные метрики одного сетевого потока (flow).
    /// Flow = пятёрка (SrcIP, DstIP, SrcPort, DstPort, Protocol) в рамках сессии.
    /// Все признаки — CICIDS-совместимые, используются для обучения ML-моделей.
    /// </summary>
    public class FlowMetrics
    {
        [Key]
        public int Id { get; set; }

        // --- Идентификация flow (5-tuple + сессия) ---
        public int SessionId { get; set; }

        [ForeignKey("SessionId")]
        public TrafficSession? Session { get; set; }

        [Required, StringLength(45)]
        public string SourceIP { get; set; } = "";

        [Required, StringLength(45)]
        public string DestinationIP { get; set; } = "";

        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }

        [Required, StringLength(10)]
        public string Protocol { get; set; } = "";

        public DateTime FlowStartTime { get; set; }
        public DateTime FlowEndTime { get; set; }

        // ========================================================
        // БЛОК: Базовые характеристики потока
        // ========================================================

        /// <summary>Общая длительность потока в микросекундах</summary>
        public double FlowDuration { get; set; }

        public int TotalFwdPackets { get; set; }
        public int TotalBackwardPackets { get; set; }
        public long TotalLengthFwdPackets { get; set; }
        public long TotalLengthBwdPackets { get; set; }

        // ========================================================
        // БЛОК: Длины пакетов (forward)
        // ========================================================
        public double FwdPacketLengthMax { get; set; }
        public double FwdPacketLengthMin { get; set; }
        public double FwdPacketLengthMean { get; set; }
        public double FwdPacketLengthStd { get; set; }

        // ========================================================
        // БЛОК: Длины пакетов (backward)
        // ========================================================
        public double BwdPacketLengthMax { get; set; }
        public double BwdPacketLengthMin { get; set; }
        public double BwdPacketLengthMean { get; set; }
        public double BwdPacketLengthStd { get; set; }

        // ========================================================
        // БЛОК: Скорости
        // ========================================================
        public double FlowBytesPerSec { get; set; }
        public double FlowPacketsPerSec { get; set; }
        public double FwdPacketsPerSec { get; set; }
        public double BwdPacketsPerSec { get; set; }

        // ========================================================
        // БЛОК: Inter-Arrival Time (IAT) — между пакетами
        // ========================================================
        public double FlowIATMean { get; set; }
        public double FlowIATStd { get; set; }
        public double FlowIATMax { get; set; }
        public double FlowIATMin { get; set; }

        public double FwdIATTotal { get; set; }
        public double FwdIATMean { get; set; }
        public double FwdIATStd { get; set; }
        public double FwdIATMax { get; set; }
        public double FwdIATMin { get; set; }

        public double BwdIATTotal { get; set; }
        public double BwdIATMean { get; set; }
        public double BwdIATStd { get; set; }
        public double BwdIATMax { get; set; }
        public double BwdIATMin { get; set; }

        // ========================================================
        // БЛОК: TCP-флаги (бинарные + счётчики)
        // ========================================================
        public int FwdPSHFlags { get; set; }
        public int BwdPSHFlags { get; set; }
        public int FwdURGFlags { get; set; }
        public int BwdURGFlags { get; set; }

        public int FINFlagCount { get; set; }
        public int SYNFlagCount { get; set; }
        public int RSTFlagCount { get; set; }
        public int PSHFlagCount { get; set; }
        public int ACKFlagCount { get; set; }
        public int URGFlagCount { get; set; }
        public int CWEFlagCount { get; set; }
        public int ECEFlagCount { get; set; }

        // ========================================================
        // БЛОК: Заголовки
        // ========================================================
        public int FwdHeaderLength { get; set; }
        public int BwdHeaderLength { get; set; }
        public int MinSegSizeForward { get; set; }

        // ========================================================
        // БЛОК: Длина пакета (агрегированно по всему flow)
        // ========================================================
        public double MinPacketLength { get; set; }
        public double MaxPacketLength { get; set; }
        public double PacketLengthMean { get; set; }
        public double PacketLengthStd { get; set; }
        public double PacketLengthVariance { get; set; }

        // ========================================================
        // БЛОК: Средние размеры
        // ========================================================
        public double AveragePacketSize { get; set; }
        public double AvgFwdSegmentSize { get; set; }
        public double AvgBwdSegmentSize { get; set; }

        public double DownUpRatio { get; set; }

        // ========================================================
        // БЛОК: Init Window (TCP)
        // ========================================================
        public int InitWinBytesForward { get; set; }
        public int InitWinBytesBackward { get; set; }
        public int ActDataPktFwd { get; set; }

        // ========================================================
        // БЛОК: Bulk (подпотоки)
        // ========================================================
        public double FwdAvgBytesBulk { get; set; }
        public double FwdAvgPacketsBulk { get; set; }
        public double FwdAvgBulkRate { get; set; }
        public double BwdAvgBytesBulk { get; set; }
        public double BwdAvgPacketsBulk { get; set; }
        public double BwdAvgBulkRate { get; set; }

        public int SubflowFwdPackets { get; set; }
        public long SubflowFwdBytes { get; set; }
        public int SubflowBwdPackets { get; set; }
        public long SubflowBwdBytes { get; set; }

        // ========================================================
        // БЛОК: Active / Idle (периоды активности)
        // ========================================================
        public double ActiveMean { get; set; }
        public double ActiveStd { get; set; }
        public double ActiveMax { get; set; }
        public double ActiveMin { get; set; }

        public double IdleMean { get; set; }
        public double IdleStd { get; set; }
        public double IdleMax { get; set; }
        public double IdleMin { get; set; }

        // ========================================================
        // БЛОК: Результаты анализа (заполняются после ML)
        // ========================================================

        /// <summary>Метка для supervised-обучения: 0 = норма, 1 = атака (если размечено)</summary>
        public int? Label { get; set; }

        /// <summary>Оценка угрозы от текущей модели (0..1)</summary>
        public double? ThreatScore { get; set; }

        /// <summary>Уровень: Low/Medium/High/Critical</summary>
        [StringLength(20)]
        public string? ThreatLevel { get; set; }

        /// <summary>Какая модель сделала предсказание: rf | catboost | ensemble</summary>
        [StringLength(20)]
        public string? PredictedBy { get; set; }
    }
}
