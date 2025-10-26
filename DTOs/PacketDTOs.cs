namespace TrafficAnalysisAPI.DTOs
{
    // DTO для создания пакета
    public class CreatePacketDto
    {
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public int PacketSize { get; set; }
        public int? SessionId { get; set; }
    }

    // DTO для обновления пакета
    public class UpdatePacketDto
    {
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public int PacketSize { get; set; }
        public int? SessionId { get; set; }
    }

    // DTO для отображения пакета
    public class PacketDto
    {
        public int Id { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public int PacketSize { get; set; }
        public DateTime Timestamp { get; set; }
        public int? SessionId { get; set; }
        public string? SessionName { get; set; }
        public AnalysisDto? Analysis { get; set; }
    }

    // DTO для балла угрозы
    public class ThreatScoreDto
    {
        public int PacketId { get; set; }
        public double ThreatScore { get; set; }
        public string Category { get; set; }
        public string Explanation { get; set; }
    }
}