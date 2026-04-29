using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
    /// <summary>
    /// Сетевой пакет. Привязан к сессии (SessionId) и, если разобран
    /// из .pcap и попал во flow — к FlowMetrics (FlowId).
    /// </summary>
    public class NetworkPacket
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(45)]
        public string SourceIP { get; set; } = "";

        [Required]
        [StringLength(45)]
        public string DestinationIP { get; set; } = "";

        public int Port { get; set; }

        [Required]
        [StringLength(30)]
        public string Protocol { get; set; } = "";

        public int PacketSize { get; set; }

        public DateTime Timestamp { get; set; }

        // --- Связи ---

        public int? SessionId { get; set; }

        [ForeignKey("SessionId")]
        public TrafficSession? Session { get; set; }

        /// <summary>
        /// ID потока (FlowMetrics) к которому принадлежит пакет.
        /// Null для пакетов вне flow (например, ARP, ICMPv6 пакеты без IP-payload).
        /// </summary>
        public int? FlowId { get; set; }

        [ForeignKey("FlowId")]
        public FlowMetrics? Flow { get; set; }

        // --- Бизнес-логика: расчёт threat score для пакета ---
        // Оставляем минимальную логику для фильтров/сортировки в UI пакетов.
        public double CalculateThreatScore()
        {
            double score = 0;

            // Подозрительные порты
            if (Port == 23 || Port == 3389 || Port == 445)
                score += 30;

            // Большой размер пакета
            if (PacketSize > 1500)
                score += 20;

            return Math.Min(score, 100);
        }
    }
}
