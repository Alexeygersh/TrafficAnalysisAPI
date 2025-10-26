namespace TrafficAnalysisAPI.DTOs
{
    public class SuspiciousPacketDto
    {
        public int PacketId { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public DateTime Timestamp { get; set; }
        public string ThreatLevel { get; set; }
        public double MLScore { get; set; }
        public string? SessionName { get; set; }
    }

    public class ThreatsByProtocolDto
    {
        public string Protocol { get; set; }
        public int TotalThreats { get; set; }
        public int CriticalThreats { get; set; }
        public int HighThreats { get; set; }
        public double AverageMLScore { get; set; }
    }

    public class TopMaliciousIPDto
    {
        public string SourceIP { get; set; }
        public int ThreatCount { get; set; }
        public string HighestThreatLevel { get; set; }
        public double AverageMLScore { get; set; }
        public DateTime LastDetected { get; set; }
        public List<string> Protocols { get; set; }
    }

    public class SourceHistoryDto
    {
        public string SourceIP { get; set; }
        public int TotalPackets { get; set; }
        public int MaliciousPackets { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public List<string> Protocols { get; set; }
        public List<SessionSummaryDto> Sessions { get; set; }
        public List<RecentAnalysisDto> RecentAnalyses { get; set; }
    }

    public class SessionSummaryDto
    {
        public int SessionId { get; set; }
        public string SessionName { get; set; }
    }

    public class RecentAnalysisDto
    {
        public int PacketId { get; set; }
        public DateTime Timestamp { get; set; }
        public string ThreatLevel { get; set; }
        public double MLScore { get; set; }
    }

    public class TimeBasedSummaryDto
    {
        public string TimeRange { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int TotalPackets { get; set; }
        public int AnalyzedPackets { get; set; }
        public int MaliciousPackets { get; set; }
        public List<ThreatDistributionDto> ThreatDistribution { get; set; }
        public List<ProtocolCountDto> TopProtocols { get; set; }
        public List<SessionSummaryStatsDto> SessionsSummary { get; set; }
    }

    public class ThreatDistributionDto
    {
        public string ThreatLevel { get; set; }
        public int Count { get; set; }
    }

    public class ProtocolCountDto
    {
        public string Protocol { get; set; }
        public int Count { get; set; }
    }

    public class SessionSummaryStatsDto
    {
        public string SessionName { get; set; }
        public int PacketCount { get; set; }
        public int MaliciousCount { get; set; }
    }
}