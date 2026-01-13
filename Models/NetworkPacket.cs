using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
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
        public string Protocol { get; set; }

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
}