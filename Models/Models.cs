using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
    // Модель пользователя
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Username { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        [StringLength(20)]
        public string Role { get; set; } // "Admin" или "Analyst"

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    // Модель сетевого пакета ()
    public class NetworkPacket
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(45)]
        public string SourceIP { get; set; }

        [Required]
        [StringLength(45)]
        public string DestinationIP { get; set; }

        [Range(0, 65535)]
        public int Port { get; set; }

        [Required]
        [StringLength(10)]
        public string Protocol { get; set; } // TCP/UDP/

        public int PacketSize { get; set; } // в байтах

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public int? SessionId { get; set; }

        [ForeignKey("SessionId")]
        public TrafficSession? Session { get; set; }

        public TrafficAnalysis? Analysis { get; set; }

        // Бизнес-логика: проверка, что пакет из того же источника
        public bool IsFromSameSource(string ipAddress)
        {
            return SourceIP.Equals(ipAddress, StringComparison.OrdinalIgnoreCase);
        }

        // Бизнес-логика: расчет базового балла угрозы
        public double CalculateThreatScore()
        {
            double score = 0;

            // Подозрительные порты
            int[] suspiciousPorts = { 23, 135, 139, 445, 3389, 5900 };
            if (suspiciousPorts.Contains(Port))
                score += 30;

            // Большой размер пакета
            if (PacketSize > 1500)
                score += 20;

            // Необычные протоколы
            if (Protocol != "TCP" && Protocol != "UDP" && Protocol != "ICMP")
                score += 15;

            return Math.Min(score, 100);
        }

        // Бизнес-логика: категория пакета
        public string GetPacketCategory()
        {
            if (Port == 80 || Port == 443)
                return "Web Traffic";
            else if (Port == 22 || Port == 23)
                return "Remote Access";
            else if (Port == 25 || Port == 110 || Port == 143)
                return "Email";
            else if (Port >= 1024)
                return "High Port";
            else
                return "Other";
        }
    }

    // Модель результата анализа трафика
    public class TrafficAnalysis
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public int PacketId { get; set; }

        [ForeignKey("PacketId")]
        public NetworkPacket Packet { get; set; }

        [Required]
        [StringLength(20)]
        public string ThreatLevel { get; set; } // Low, Medium, High, Critical

        public bool IsMalicious { get; set; }

        [Range(0, 1)]
        public double MLModelScore { get; set; } // 0.0 - 1.0 (вероятность угрозы)

        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

        [StringLength(500)]
        public string? Description { get; set; }

        // Бизнес-логика: классификация уровня угрозы на основе ML-score
        public void ClassifyThreat()
        {
            if (MLModelScore >= 0.8)
            {
                ThreatLevel = "Critical";
                IsMalicious = true;
            }
            else if (MLModelScore >= 0.6)
            {
                ThreatLevel = "High";
                IsMalicious = true;
            }
            else if (MLModelScore >= 0.4)
            {
                ThreatLevel = "Medium";
                IsMalicious = false;
            }
            else
            {
                ThreatLevel = "Low";
                IsMalicious = false;
            }
        }

        // Бизнес-логика: генерация описания отчета
        public string GenerateReport()
        {
            var report = $"Анализ пакета #{PacketId}\n";
            report += $"Источник: {Packet.SourceIP}:{Packet.Port}\n";
            report += $"Назначение: {Packet.DestinationIP}\n";
            report += $"Уровень угрозы: {ThreatLevel}\n";
            report += $"ML-score: {MLModelScore:F2}\n";
            report += $"Статус: {(IsMalicious ? "Вредоносный" : "Безопасный")}\n";
            report += $"Дата обнаружения: {DetectedAt:yyyy-MM-dd HH:mm:ss}";

            return report;
        }

        // Бизнес-логика: обновление уверенности модели
        public void UpdateConfidence(double newScore)
        {
            MLModelScore = (MLModelScore + newScore) / 2.0;
            ClassifyThreat();
        }
    }

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