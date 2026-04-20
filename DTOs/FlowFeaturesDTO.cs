namespace TrafficAnalysisAPI.DTOs
{
    /// <summary>
    /// DTO для одного flow, построенного Python-модулем flow_features.py.
    /// Содержит все ~78 признаков из CICFlowMeter.
    /// Используется для передачи данных между C# и Python + сохранения в БД.
    /// </summary>
    public class FlowFeaturesDto
    {
        // --- Идентификация ---
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public double FlowStartTime { get; set; }
        public double FlowEndTime { get; set; }

        // --- Базовые ---
        public double FlowDuration { get; set; }
        public int TotalFwdPackets { get; set; }
        public int TotalBackwardPackets { get; set; }
        public long TotalLengthFwdPackets { get; set; }
        public long TotalLengthBwdPackets { get; set; }

        // --- Длины пакетов ---
        public double FwdPacketLengthMax { get; set; }
        public double FwdPacketLengthMin { get; set; }
        public double FwdPacketLengthMean { get; set; }
        public double FwdPacketLengthStd { get; set; }
        public double BwdPacketLengthMax { get; set; }
        public double BwdPacketLengthMin { get; set; }
        public double BwdPacketLengthMean { get; set; }
        public double BwdPacketLengthStd { get; set; }

        // --- Скорости ---
        public double FlowBytesPerSec { get; set; }
        public double FlowPacketsPerSec { get; set; }
        public double FwdPacketsPerSec { get; set; }
        public double BwdPacketsPerSec { get; set; }

        // --- IAT ---
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

        // --- TCP Flags ---
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

        // --- Headers ---
        public int FwdHeaderLength { get; set; }
        public int BwdHeaderLength { get; set; }
        public int MinSegSizeForward { get; set; }

        // --- Packet length aggregates ---
        public double MinPacketLength { get; set; }
        public double MaxPacketLength { get; set; }
        public double PacketLengthMean { get; set; }
        public double PacketLengthStd { get; set; }
        public double PacketLengthVariance { get; set; }

        // --- Средние размеры ---
        public double AveragePacketSize { get; set; }
        public double AvgFwdSegmentSize { get; set; }
        public double AvgBwdSegmentSize { get; set; }
        public double DownUpRatio { get; set; }

        // --- Init Window + payload ---
        public int InitWinBytesForward { get; set; }
        public int InitWinBytesBackward { get; set; }
        public int ActDataPktFwd { get; set; }

        // --- Bulk ---
        public double FwdAvgBytesBulk { get; set; }
        public double FwdAvgPacketsBulk { get; set; }
        public double FwdAvgBulkRate { get; set; }
        public double BwdAvgBytesBulk { get; set; }
        public double BwdAvgPacketsBulk { get; set; }
        public double BwdAvgBulkRate { get; set; }

        // --- Subflow ---
        public int SubflowFwdPackets { get; set; }
        public long SubflowFwdBytes { get; set; }
        public int SubflowBwdPackets { get; set; }
        public long SubflowBwdBytes { get; set; }

        // --- Active / Idle ---
        public double ActiveMean { get; set; }
        public double ActiveStd { get; set; }
        public double ActiveMax { get; set; }
        public double ActiveMin { get; set; }
        public double IdleMean { get; set; }
        public double IdleStd { get; set; }
        public double IdleMax { get; set; }
        public double IdleMin { get; set; }
    }

    /// <summary>
    /// Результат импорта .pcap файла.
    /// </summary>
    public class PcapImportResultDto
    {
        public int SessionId { get; set; }
        public string SessionName { get; set; } = "";
        public int RawPacketsParsed { get; set; }
        public int FlowsBuilt { get; set; }
        public int FlowsSavedToDb { get; set; }
        public Dictionary<string, int> ProtocolStats { get; set; } = new();
        public long ElapsedMs { get; set; }
    }
}
