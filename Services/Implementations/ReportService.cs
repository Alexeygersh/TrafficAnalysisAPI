using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Services.Implementations
{
    public class ReportService : IReportService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ReportService> _logger;

        public ReportService(ApplicationDbContext context, ILogger<ReportService> logger)
        {
            _context = context;
            _logger = logger;
        }

        // 1. LINQ: Подозрительные пакеты с анализом
        public async Task<IEnumerable<SuspiciousPacketDto>> GetSuspiciousPacketsAsync()
        {
            var suspiciousPackets = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Include(p => p.Session)
                .Where(p => p.Analysis != null && p.Analysis.IsMalicious)
                .Select(p => new SuspiciousPacketDto
                {
                    PacketId = p.Id,
                    SourceIP = p.SourceIP,
                    DestinationIP = p.DestinationIP,
                    Port = p.Port,
                    Protocol = p.Protocol,
                    Timestamp = p.Timestamp,
                    ThreatLevel = p.Analysis!.ThreatLevel,
                    MLScore = p.Analysis.MLModelScore,
                    SessionName = p.Session != null ? p.Session.SessionName : null
                })
                .OrderByDescending(p => p.MLScore)
                .ToListAsync();

            _logger.LogInformation($"Found {suspiciousPackets.Count} suspicious packets");
            return suspiciousPackets;
        }

        // 2. LINQ: Угрозы по протоколам
        public async Task<IEnumerable<ThreatsByProtocolDto>> GetThreatsByProtocolAsync()
        {
            var threatStats = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Where(p => p.Analysis != null && p.Analysis.IsMalicious)
                .GroupBy(p => p.Protocol)
                .Select(g => new ThreatsByProtocolDto
                {
                    Protocol = g.Key,
                    TotalThreats = g.Count(),
                    CriticalThreats = g.Count(p => p.Analysis!.ThreatLevel == "Critical"),
                    HighThreats = g.Count(p => p.Analysis!.ThreatLevel == "High"),
                    AverageMLScore = g.Average(p => p.Analysis!.MLModelScore)
                })
                .OrderByDescending(s => s.TotalThreats)
                .ToListAsync();

            return threatStats;
        }

        // 3. LINQ: Топ вредоносных IP
        public async Task<IEnumerable<TopMaliciousIPDto>> GetTopMaliciousIPsAsync(int top = 10)
        {
            var topIPs = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Where(p => p.Analysis != null && p.Analysis.IsMalicious)
                .GroupBy(p => p.SourceIP)
                .Select(g => new TopMaliciousIPDto
                {
                    SourceIP = g.Key,
                    ThreatCount = g.Count(),
                    HighestThreatLevel = g.Max(p => p.Analysis!.ThreatLevel) ?? "Unknown",
                    AverageMLScore = g.Average(p => p.Analysis!.MLModelScore),
                    LastDetected = g.Max(p => p.Timestamp),
                    Protocols = g.Select(p => p.Protocol).Distinct().ToList()
                })
                .OrderByDescending(s => s.ThreatCount)
                .Take(top)
                .ToListAsync();

            return topIPs;
        }

        // 4. LINQ: История источника
        public async Task<SourceHistoryDto?> GetSourceHistoryAsync(string sourceIP)
        {
            var packets = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Include(p => p.Session)
                .Where(p => p.SourceIP == sourceIP)
                .ToListAsync();

            if (!packets.Any())
                return null;

            var history = new SourceHistoryDto
            {
                SourceIP = sourceIP,
                TotalPackets = packets.Count,
                MaliciousPackets = packets.Count(p => p.Analysis != null && p.Analysis.IsMalicious),
                FirstSeen = packets.Min(p => p.Timestamp),
                LastSeen = packets.Max(p => p.Timestamp),
                Protocols = packets.Select(p => p.Protocol).Distinct().ToList(),
                Sessions = packets
                    .Where(p => p.Session != null)
                    .Select(p => new SessionSummaryDto
                    {
                        SessionId = p.SessionId!.Value,
                        SessionName = p.Session!.SessionName
                    })
                    .Distinct()
                    .ToList(),
                RecentAnalyses = packets
                    .Where(p => p.Analysis != null)
                    .OrderByDescending(p => p.Timestamp)
                    .Take(5)
                    .Select(p => new RecentAnalysisDto
                    {
                        PacketId = p.Id,
                        Timestamp = p.Timestamp,
                        ThreatLevel = p.Analysis!.ThreatLevel,
                        MLScore = p.Analysis.MLModelScore
                    })
                    .ToList()
            };

            return history;
        }

        // 5. LINQ: Сводка по времени
        public async Task<TimeBasedSummaryDto> GetTimeBasedSummaryAsync(int hours = 24)
        {
            var startTime = DateTime.UtcNow.AddHours(-hours);

            var packets = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Include(p => p.Session)
                .Where(p => p.Timestamp >= startTime)
                .ToListAsync();

            var summary = new TimeBasedSummaryDto
            {
                TimeRange = $"Последние {hours} часов",
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                TotalPackets = packets.Count,
                AnalyzedPackets = packets.Count(p => p.Analysis != null),
                MaliciousPackets = packets.Count(p => p.Analysis != null && p.Analysis.IsMalicious),
                ThreatDistribution = packets
                    .Where(p => p.Analysis != null && p.Analysis.IsMalicious)
                    .GroupBy(p => p.Analysis!.ThreatLevel)
                    .Select(g => new ThreatDistributionDto
                    {
                        ThreatLevel = g.Key,
                        Count = g.Count()
                    })
                    .ToList(),
                TopProtocols = packets
                    .GroupBy(p => p.Protocol)
                    .Select(g => new ProtocolCountDto
                    {
                        Protocol = g.Key,
                        Count = g.Count()
                    })
                    .OrderByDescending(p => p.Count)
                    .Take(5)
                    .ToList(),
                SessionsSummary = packets
                    .Where(p => p.Session != null)
                    .GroupBy(p => p.Session!.SessionName)
                    .Select(g => new SessionSummaryStatsDto
                    {
                        SessionName = g.Key,
                        PacketCount = g.Count(),
                        MaliciousCount = g.Count(p => p.Analysis != null && p.Analysis.IsMalicious)
                    })
                    .ToList()
            };

            return summary;
        }

        // 6. LINQ: Детальный отчет по сессии
        public async Task<SessionStatisticsDto?> GetSessionDetailedReportAsync(int sessionId)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .ThenInclude(p => p.Analysis)
                .FirstOrDefaultAsync(s => s.Id == sessionId);

            if (session == null) return null;

            var totalPackets = session.Packets?.Count ?? 0;
            var packets = session.Packets ?? new List<Models.NetworkPacket>();

            return new SessionStatisticsDto
            {
                SessionId = session.Id,
                SessionName = session.SessionName,
                TotalPackets = totalPackets,
                UniqueSourceIPs = packets.Select(p => p.SourceIP).Distinct().Count(),
                UniqueDestinationIPs = packets.Select(p => p.DestinationIP).Distinct().Count(),
                AveragePacketSize = packets.Any() ? packets.Average(p => p.PacketSize) : 0,
                MostUsedProtocol = packets
                    .GroupBy(p => p.Protocol)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault()?.Key ?? "N/A",
                AnomalousPacketsCount = packets
                    .Count(p => p.Analysis != null && p.Analysis.IsMalicious),
                DurationMinutes = session.EndTime.HasValue
                    ? (session.EndTime.Value - session.StartTime).TotalMinutes
                    : (DateTime.UtcNow - session.StartTime).TotalMinutes
            };
        }
    }
}