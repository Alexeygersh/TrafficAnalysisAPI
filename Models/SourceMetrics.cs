using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TrafficAnalysisAPI.Models
{
    public class SourceMetrics
    {
        [Key]
        public int Id { get; set; }

        public int? SessionId { get; set; }

        [ForeignKey("SessionId")]
        public TrafficSession? Session { get; set; }

        [Required]
        [StringLength(45)]
        required public string SourceIP { get; set; }

        public int PacketCount { get; set; }
        public double PacketsPerSecond { get; set; }
        public double AveragePacketSize { get; set; }
        public long TotalBytes { get; set; }
        public double Duration { get; set; }

        public int ClusterId { get; set; }
        public bool IsDangerous { get; set; }
        public double DangerScore { get; set; }


        [StringLength(100)]
        public string? ClusterName { get; set; }

        public int UniquePorts { get; set; }

        [StringLength(500)]
        public string? Protocols { get; set; } // Сохраняем как CSV строку

        public DateTime CalculatedAt { get; set; } = DateTime.UtcNow;
    }
}