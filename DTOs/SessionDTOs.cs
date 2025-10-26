namespace TrafficAnalysisAPI.DTOs
{
    public class CreateSessionDto
    {
        public string SessionName { get; set; }
        public string? Description { get; set; }
    }

    public class SessionDto
    {
        public int Id { get; set; }
        public string SessionName { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string? Description { get; set; }
        public int TotalPackets { get; set; }
        public bool IsActive => !EndTime.HasValue;
    }

    public class SessionStatisticsDto
    {
        public int SessionId { get; set; }
        public string SessionName { get; set; }
        public int TotalPackets { get; set; }
        public int UniqueSourceIPs { get; set; }
        public int UniqueDestinationIPs { get; set; }
        public double AveragePacketSize { get; set; }
        public string MostUsedProtocol { get; set; }
        public int AnomalousPacketsCount { get; set; }
        public double DurationMinutes { get; set; }
    }
}