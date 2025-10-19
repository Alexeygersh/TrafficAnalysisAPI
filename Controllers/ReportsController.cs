using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AuthorizedUser")] // Все отчеты только для авторизованных
    public class ReportsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public ReportsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // 1. LINQ-запрос: Все подозрительные пакеты с результатами анализа
        // GET: api/Reports/suspicious-packets
        [HttpGet("suspicious-packets")]
        public async Task<ActionResult<IEnumerable<object>>> GetSuspiciousPackets()
        {
            var suspiciousPackets = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Include(p => p.Session)
                .Where(p => p.Analysis != null && p.Analysis.IsMalicious) // LINQ Where
                .Select(p => new // LINQ Select
                {
                    PacketId = p.Id,
                    SourceIP = p.SourceIP,
                    DestinationIP = p.DestinationIP,
                    Port = p.Port,
                    Protocol = p.Protocol,
                    Timestamp = p.Timestamp,
                    ThreatLevel = p.Analysis.ThreatLevel,
                    MLScore = p.Analysis.MLModelScore,
                    SessionName = p.Session != null ? p.Session.SessionName : "Без сессии"
                })
                .OrderByDescending(p => p.MLScore)
                .ToListAsync();

            return Ok(suspiciousPackets);
        }

        // 2. LINQ-запрос: Статистика по сессиям (количество угроз по протоколам)
        // GET: api/Reports/threats-by-protocol
        [HttpGet("threats-by-protocol")]
        public async Task<ActionResult<IEnumerable<object>>> GetThreatsByProtocol()
        {
            var threatStats = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Where(p => p.Analysis != null && p.Analysis.IsMalicious) // LINQ Where
                .GroupBy(p => p.Protocol) // LINQ GroupBy
                .Select(g => new // LINQ Select
                {
                    Protocol = g.Key,
                    TotalThreats = g.Count(),
                    CriticalThreats = g.Count(p => p.Analysis.ThreatLevel == "Critical"),
                    HighThreats = g.Count(p => p.Analysis.ThreatLevel == "High"),
                    AverageMLScore = g.Average(p => p.Analysis.MLModelScore)
                })
                .OrderByDescending(s => s.TotalThreats)
                .ToListAsync();

            return Ok(threatStats);
        }

        // 3. LINQ-запрос: Топ IP-адресов по количеству аномалий
        // GET: api/Reports/top-malicious-ips
        [HttpGet("top-malicious-ips")]
        public async Task<ActionResult<IEnumerable<object>>> GetTopMaliciousIPs([FromQuery] int top = 10)
        {
            var topIPs = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Where(p => p.Analysis != null && p.Analysis.IsMalicious) // LINQ Where
                .GroupBy(p => p.SourceIP) // LINQ GroupBy
                .Select(g => new // LINQ Select
                {
                    SourceIP = g.Key,
                    ThreatCount = g.Count(),
                    HighestThreatLevel = g.Max(p => p.Analysis.ThreatLevel),
                    AverageMLScore = g.Average(p => p.Analysis.MLModelScore),
                    LastDetected = g.Max(p => p.Timestamp),
                    Protocols = g.Select(p => p.Protocol).Distinct().ToList()
                })
                .OrderByDescending(s => s.ThreatCount)
                .Take(top)
                .ToListAsync();

            return Ok(topIPs);
        }

        // 4. LINQ-запрос: История анализа для конкретного источника
        // GET: api/Reports/source-history/192.168.1.100
        [HttpGet("source-history/{sourceIP}")]
        public async Task<ActionResult<object>> GetSourceHistory(string sourceIP)
        {
            var packets = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Include(p => p.Session)
                .Where(p => p.SourceIP == sourceIP) // LINQ Where
                .ToListAsync();

            if (!packets.Any())
                return NotFound(new { message = "Пакеты от данного источника не найдены" });

            var history = new
            {
                SourceIP = sourceIP,
                TotalPackets = packets.Count,
                MaliciousPackets = packets.Count(p => p.Analysis != null && p.Analysis.IsMalicious),
                FirstSeen = packets.Min(p => p.Timestamp),
                LastSeen = packets.Max(p => p.Timestamp),
                Protocols = packets.Select(p => p.Protocol).Distinct().ToList(), // LINQ Select + Distinct
                Sessions = packets
                    .Where(p => p.Session != null) // LINQ Where
                    .Select(p => new // LINQ Select
                    {
                        SessionId = p.SessionId,
                        SessionName = p.Session.SessionName
                    })
                    .Distinct()
                    .ToList(),
                RecentAnalyses = packets
                    .Where(p => p.Analysis != null) // LINQ Where
                    .OrderByDescending(p => p.Timestamp)
                    .Take(5)
                    .Select(p => new // LINQ Select
                    {
                        PacketId = p.Id,
                        Timestamp = p.Timestamp,
                        ThreatLevel = p.Analysis.ThreatLevel,
                        MLScore = p.Analysis.MLModelScore
                    })
                    .ToList()
            };

            return Ok(history);
        }

        // 5. LINQ-запрос: Сводный отчет по временным интервалам
        // GET: api/Reports/time-based-summary?hours=24
        [HttpGet("time-based-summary")]
        public async Task<ActionResult<object>> GetTimeBasedSummary([FromQuery] int hours = 24)
        {
            var startTime = DateTime.UtcNow.AddHours(-hours);

            var packets = await _context.NetworkPackets
                .Include(p => p.Analysis)
                .Include(p => p.Session)
                .Where(p => p.Timestamp >= startTime) // LINQ Where
                .ToListAsync();

            var summary = new
            {
                TimeRange = $"Последние {hours} часов",
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                TotalPackets = packets.Count,
                AnalyzedPackets = packets.Count(p => p.Analysis != null),
                MaliciousPackets = packets.Count(p => p.Analysis != null && p.Analysis.IsMalicious),
                ThreatDistribution = packets
                    .Where(p => p.Analysis != null && p.Analysis.IsMalicious) // LINQ Where
                    .GroupBy(p => p.Analysis.ThreatLevel) // LINQ GroupBy
                    .Select(g => new { ThreatLevel = g.Key, Count = g.Count() }) // LINQ Select
                    .ToList(),
                TopProtocols = packets
                    .GroupBy(p => p.Protocol) // LINQ GroupBy
                    .Select(g => new { Protocol = g.Key, Count = g.Count() }) // LINQ Select
                    .OrderByDescending(p => p.Count)
                    .Take(5)
                    .ToList(),
                SessionsSummary = packets
                    .Where(p => p.Session != null) // LINQ Where
                    .GroupBy(p => p.Session.SessionName) // LINQ GroupBy
                    .Select(g => new // LINQ Select
                    {
                        SessionName = g.Key,
                        PacketCount = g.Count(),
                        MaliciousCount = g.Count(p => p.Analysis != null && p.Analysis.IsMalicious)
                    })
                    .ToList()
            };

            return Ok(summary);
        }

        // 6. LINQ-запрос: Детальный отчет по сессии с анализом
        // GET: api/Reports/session-detailed/5
        [HttpGet("session-detailed/{sessionId}")]
        public async Task<ActionResult<object>> GetDetailedSessionReport(int sessionId)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .ThenInclude(p => p.Analysis)
                .Where(s => s.Id == sessionId) // LINQ Where
                .FirstOrDefaultAsync();

            if (session == null)
                return NotFound(new { message = "Сессия не найдена" });

            var report = new
            {
                SessionId = session.Id,
                SessionName = session.SessionName,
                StartTime = session.StartTime,
                EndTime = session.EndTime,
                TotalPackets = session.Packets.Count,
                Statistics = session.CalculateStatistics(),
                PacketsByProtocol = session.Packets
                    .GroupBy(p => p.Protocol) // LINQ GroupBy
                    .Select(g => new { Protocol = g.Key, Count = g.Count() }) // LINQ Select
                    .OrderByDescending(p => p.Count)
                    .ToList(),
                ThreatAnalysis = session.Packets
                    .Where(p => p.Analysis != null) // LINQ Where
                    .Select(p => new // LINQ Select
                    {
                        PacketId = p.Id,
                        SourceIP = p.SourceIP,
                        DestinationIP = p.DestinationIP,
                        ThreatLevel = p.Analysis.ThreatLevel,
                        IsMalicious = p.Analysis.IsMalicious,
                        MLScore = p.Analysis.MLModelScore
                    })
                    .ToList(),
                AnomalousPackets = session.GetAnomalousPackets()
                    .Select(p => new // LINQ Select
                    {
                        PacketId = p.Id,
                        SourceIP = p.SourceIP,
                        ThreatScore = p.CalculateThreatScore(),
                        Category = p.GetPacketCategory()
                    })
                    .ToList()
            };

            return Ok(report);
        }
    }
}