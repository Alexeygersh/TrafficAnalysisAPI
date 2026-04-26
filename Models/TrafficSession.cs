using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
    /// <summary>
    /// Сессия мониторинга трафика. Одна сессия = один импорт .pcap
    /// (или набор связанных пакетов). Содержит коллекции NetworkPackets
    /// и FlowMetrics.
    /// </summary>
    public class TrafficSession
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string SessionName { get; set; } = "";

        public DateTime StartTime { get; set; } = DateTime.UtcNow;

        public DateTime? EndTime { get; set; }

        [StringLength(200)]
        public string? Description { get; set; }

        // --- Навигационные коллекции ---

        public List<NetworkPacket> Packets { get; set; } = new();
        public List<FlowMetrics> Flows { get; set; } = new();

        // --- Computed ---

        [NotMapped]
        public int TotalPackets => Packets?.Count ?? 0;

        [NotMapped]
        public int TotalFlows => Flows?.Count ?? 0;

        [NotMapped]
        public bool IsActive => !EndTime.HasValue;

        // --- Бизнес-логика ---

        public void AddPacket(NetworkPacket packet)
        {
            if (EndTime.HasValue)
                throw new InvalidOperationException(
                    "Нельзя добавлять пакеты в завершённую сессию");

            Packets.Add(packet);
            packet.SessionId = this.Id;
        }
    }
}

