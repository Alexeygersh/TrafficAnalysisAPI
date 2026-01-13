namespace TrafficAnalysisAPI.DTOs
{
    public class SourceMetricsDto
    {
        public required string SourceIP { get; set; }
        public int PacketCount { get; set; }
        public double PacketsPerSecond { get; set; }
        public double AveragePacketSize { get; set; }
        public long TotalBytes { get; set; }
        public double Duration { get; set; }
        public required List<string> Protocols { get; set; }
        public int UniquePorts { get; set; }
    }

    public class SourceClusterResultDto
    {
        public required string SourceIP { get; set; }
        public int PacketCount { get; set; }
        public double PacketsPerSecond { get; set; }
        public double AveragePacketSize { get; set; }
        public long TotalBytes { get; set; }
        public int ClusterId { get; set; }
        public bool IsDangerous { get; set; }
        public double DangerScore { get; set; }
        public required string ClusterName { get; set; }
        public int UniquePorts { get; set; }
    }

    public class PacketThreatResultDto
    {
        public double ThreatScore { get; set; }
        public required string ThreatLevel { get; set; }
        public bool IsMalicious { get; set; }
        public required List<string> Reasons { get; set; }
    }

    public class ParsedPacketDto
    {
        public int No { get; set; }
        public double Time { get; set; }
        public required string SourceIP { get; set; }
        public required string DestinationIP { get; set; }
        public required string Protocol { get; set; }
        public int Length { get; set; }
        public int Port { get; set; }
        public required string Info { get; set; }
    }
}