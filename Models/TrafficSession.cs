using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{

    // Модель сессии мониторинга трафика
    public class TrafficSession
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string SessionName { get; set; }

        public DateTime StartTime { get; set; } = DateTime.UtcNow;

        public DateTime? EndTime { get; set; }

        public List<NetworkPacket> Packets { get; set; } = new List<NetworkPacket>();

        [NotMapped]
        public int TotalPackets => Packets?.Count ?? 0;

        [StringLength(200)]
        public string? Description { get; set; }

        // Бизнес-логика: добавление пакета в сессию
        public void AddPacket(NetworkPacket packet)
        {
            if (EndTime.HasValue)
                throw new InvalidOperationException("Нельзя добавлять пакеты в завершенную сессию");

            Packets.Add(packet);
            packet.SessionId = this.Id;
        }

        // Бизнес-логика: получение аномальных пакетов
        public List<NetworkPacket> GetAnomalousPackets()
        {
            return Packets
                .Where(p => p.CalculateThreatScore() > 50)
                .OrderByDescending(p => p.CalculateThreatScore())
                .ToList();
        }

        // Бизнес-логика: расчет статистики сессии
        public Dictionary<string, object> CalculateStatistics()
        {
            var stats = new Dictionary<string, object>
            {
                ["TotalPackets"] = TotalPackets,
                ["UniqueSourceIPs"] = Packets.Select(p => p.SourceIP).Distinct().Count(),
                ["UniqueDestinationIPs"] = Packets.Select(p => p.DestinationIP).Distinct().Count(),
                ["AveragePacketSize"] = Packets.Any() ? Packets.Average(p => p.PacketSize) : 0,
                ["MostUsedProtocol"] = Packets.GroupBy(p => p.Protocol)
                                              .OrderByDescending(g => g.Count())
                                              .FirstOrDefault()?.Key ?? "N/A",
                ["AnomalousPacketsCount"] = GetAnomalousPackets().Count,
                ["Duration"] = EndTime.HasValue
                    ? (EndTime.Value - StartTime).TotalMinutes
                    : (DateTime.UtcNow - StartTime).TotalMinutes
            };

            return stats;
        }
    }
}