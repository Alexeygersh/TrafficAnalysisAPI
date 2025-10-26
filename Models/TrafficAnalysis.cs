using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
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
}