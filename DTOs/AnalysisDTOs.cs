namespace TrafficAnalysisAPI.DTOs
{
    public class CreateAnalysisDto
    {
        public int PacketId { get; set; }
        public double? MLModelScore { get; set; }
        public string? Description { get; set; }
    }

    public class AnalysisDto
    {
        public int Id { get; set; }
        public int PacketId { get; set; }
        public string ThreatLevel { get; set; }
        public bool IsMalicious { get; set; }
        public double MLModelScore { get; set; }
        public DateTime DetectedAt { get; set; }
        public string? Description { get; set; }
    }

    public class AnalysisReportDto
    {
        public int AnalysisId { get; set; }
        public int PacketId { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int Port { get; set; }
        public string ThreatLevel { get; set; }
        public double MLModelScore { get; set; }
        public bool IsMalicious { get; set; }
        public DateTime DetectedAt { get; set; }
        public string ReportText { get; set; }
    }
}