using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;
using TrafficAnalysisAPI.Utils;

namespace TrafficAnalysisAPI.Services.Implementations
{
    public class SessionService : ISessionService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<SessionService> _logger;

        public SessionService(ApplicationDbContext context, ILogger<SessionService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<SessionDto>> GetAllSessionsAsync()
        {
            var sessions = await _context.TrafficSessions
                .Include(s => s.Packets)
                .OrderByDescending(s => s.StartTime)
                .ToListAsync();

            return sessions.Select(MapToDto);
        }

        public async Task<SessionDto?> GetSessionByIdAsync(int id)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .FirstOrDefaultAsync(s => s.Id == id);

            return session == null ? null : MapToDto(session);
        }

        public async Task<SessionDto> CreateSessionAsync(CreateSessionDto dto)
        {
            var session = new TrafficSession
            {
                SessionName = dto.SessionName,
                Description = dto.Description,
                StartTime = DateTime.UtcNow
            };

            _context.TrafficSessions.Add(session);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Created session {session.Id}: {session.SessionName}");

            return await GetSessionByIdAsync(session.Id)
                ?? throw new InvalidOperationException("Failed to retrieve created session");
        }

        public async Task<bool> UpdateSessionAsync(int id, CreateSessionDto dto)
        {
            var session = await _context.TrafficSessions.FindAsync(id);
            if (session == null) return false;

            session.SessionName = dto.SessionName;
            session.Description = dto.Description;

            await _context.SaveChangesAsync();
            _logger.LogInformation($"Updated session {id}");

            return true;
        }

        public async Task<bool> DeleteSessionAsync(int id)
        {
            var session = await _context.TrafficSessions.FindAsync(id);
            if (session == null) return false;

            _context.TrafficSessions.Remove(session);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Deleted session {id}");
            return true;
        }

        public async Task<SessionStatisticsDto?> GetSessionStatisticsAsync(int id)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null) return null;

            var stats = CalculateStatistics(session);

            return new SessionStatisticsDto
            {
                SessionId = session.Id,
                SessionName = session.SessionName,
                TotalPackets = stats["TotalPackets"],
                UniqueSourceIPs = stats["UniqueSourceIPs"],
                UniqueDestinationIPs = stats["UniqueDestinationIPs"],
                AveragePacketSize = stats["AveragePacketSize"],
                MostUsedProtocol = stats["MostUsedProtocol"].ToString() ?? "N/A",
                AnomalousPacketsCount = stats["AnomalousPacketsCount"],
                DurationMinutes = stats["Duration"]
            };
        }

        public async Task<IEnumerable<PacketDto>> GetAnomalousPacketsAsync(int id)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .ThenInclude(p => p.Analysis)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null) return Enumerable.Empty<PacketDto>();

            var anomalousPackets = session.Packets
                .Where(p => CalculateThreatScore(p) > Constants.ThreatScoreThreshold)
                .OrderByDescending(p => CalculateThreatScore(p))
                .Select(MapPacketToDto)
                .ToList();

            return anomalousPackets;
        }

        public async Task<bool> CloseSessionAsync(int id)
        {
            var session = await _context.TrafficSessions.FindAsync(id);
            if (session == null) return false;

            if (session.EndTime.HasValue)
                throw new InvalidOperationException("Сессия уже завершена");

            session.EndTime = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Closed session {id}");
            return true;
        }

        // Бизнес-логика: расчет статистики сессии
        private Dictionary<string, dynamic> CalculateStatistics(TrafficSession session)
        {
            var stats = new Dictionary<string, dynamic>
            {
                ["TotalPackets"] = session.Packets?.Count ?? 0,
                ["UniqueSourceIPs"] = session.Packets?.Select(p => p.SourceIP).Distinct().Count() ?? 0,
                ["UniqueDestinationIPs"] = session.Packets?.Select(p => p.DestinationIP).Distinct().Count() ?? 0,
                ["AveragePacketSize"] = session.Packets?.Any() == true
                    ? session.Packets.Average(p => p.PacketSize)
                    : 0.0,
                ["MostUsedProtocol"] = session.Packets?
                    .GroupBy(p => p.Protocol)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault()?.Key ?? "N/A",
                ["AnomalousPacketsCount"] = session.Packets?
                    .Count(p => CalculateThreatScore(p) > Constants.ThreatScoreThreshold) ?? 0,
                ["Duration"] = session.EndTime.HasValue
                    ? (session.EndTime.Value - session.StartTime).TotalMinutes
                    : (DateTime.UtcNow - session.StartTime).TotalMinutes
            };

            return stats;
        }

        // Расчет балла угрозы для пакета
        private double CalculateThreatScore(NetworkPacket packet)
        {
            double score = 0;

            if (Constants.SuspiciousPorts.Contains(packet.Port))
                score += 30;

            if (packet.PacketSize > Constants.StandardPacketSize)
                score += 20;

            if (!Constants.StandardProtocols.Contains(packet.Protocol))
                score += 15;

            return Math.Min(score, 100);
        }

        // Маппинг Entity -> DTO
        private SessionDto MapToDto(TrafficSession session)
        {
            return new SessionDto
            {
                Id = session.Id,
                SessionName = session.SessionName,
                StartTime = session.StartTime,
                EndTime = session.EndTime,
                Description = session.Description,
                TotalPackets = session.Packets?.Count ?? 0
            };
        }

        private PacketDto MapPacketToDto(NetworkPacket packet)
        {
            return new PacketDto
            {
                Id = packet.Id,
                SourceIP = packet.SourceIP,
                DestinationIP = packet.DestinationIP,
                Port = packet.Port,
                Protocol = packet.Protocol,
                PacketSize = packet.PacketSize,
                Timestamp = packet.Timestamp,
                SessionId = packet.SessionId,
                SessionName = packet.Session?.SessionName,
                Analysis = packet.Analysis == null ? null : new AnalysisDto
                {
                    Id = packet.Analysis.Id,
                    PacketId = packet.Analysis.PacketId,
                    ThreatLevel = packet.Analysis.ThreatLevel,
                    IsMalicious = packet.Analysis.IsMalicious,
                    MLModelScore = packet.Analysis.MLModelScore,
                    DetectedAt = packet.Analysis.DetectedAt,
                    Description = packet.Analysis.Description
                }
            };
        }
    }
}