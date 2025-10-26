using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;
using TrafficAnalysisAPI.Utils;

namespace TrafficAnalysisAPI.Services.Implementations
{
    public class PacketService : IPacketService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<PacketService> _logger;

        public PacketService(ApplicationDbContext context, ILogger<PacketService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<PacketDto>> GetAllPacketsAsync()
        {
            var packets = await _context.NetworkPackets
                .Include(p => p.Session)
                .Include(p => p.Analysis)
                .OrderByDescending(p => p.Timestamp)
                .ToListAsync();

            return packets.Select(MapToDto);
        }

        public async Task<PacketDto?> GetPacketByIdAsync(int id)
        {
            var packet = await _context.NetworkPackets
                .Include(p => p.Session)
                .Include(p => p.Analysis)
                .FirstOrDefaultAsync(p => p.Id == id);

            return packet == null ? null : MapToDto(packet);
        }

        public async Task<PacketDto> CreatePacketAsync(CreatePacketDto dto)
        {
            var packet = new NetworkPacket
            {
                SourceIP = dto.SourceIP,
                DestinationIP = dto.DestinationIP,
                Port = dto.Port,
                Protocol = dto.Protocol,
                PacketSize = dto.PacketSize,
                SessionId = dto.SessionId,
                Timestamp = DateTime.UtcNow
            };

            _context.NetworkPackets.Add(packet);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Created packet {packet.Id} from {packet.SourceIP}");

            return await GetPacketByIdAsync(packet.Id)
                ?? throw new InvalidOperationException("Failed to retrieve created packet");
        }

        public async Task<bool> UpdatePacketAsync(int id, UpdatePacketDto dto)
        {
            var packet = await _context.NetworkPackets.FindAsync(id);
            if (packet == null) return false;

            packet.SourceIP = dto.SourceIP;
            packet.DestinationIP = dto.DestinationIP;
            packet.Port = dto.Port;
            packet.Protocol = dto.Protocol;
            packet.PacketSize = dto.PacketSize;
            packet.SessionId = dto.SessionId;

            await _context.SaveChangesAsync();
            _logger.LogInformation($"Updated packet {id}");

            return true;
        }

        public async Task<bool> DeletePacketAsync(int id)
        {
            var packet = await _context.NetworkPackets.FindAsync(id);
            if (packet == null) return false;

            _context.NetworkPackets.Remove(packet);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Deleted packet {id}");
            return true;
        }

        public async Task<ThreatScoreDto?> GetThreatScoreAsync(int id)
        {
            var packet = await _context.NetworkPackets.FindAsync(id);
            if (packet == null) return null;

            double score = CalculateThreatScore(packet);
            string category = GetPacketCategory(packet.Port);
            string explanation = GetThreatExplanation(packet, score);

            return new ThreatScoreDto
            {
                PacketId = packet.Id,
                ThreatScore = score,
                Category = category,
                Explanation = explanation
            };
        }

        // Бизнес-логика: расчет балла угрозы
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

        private string GetPacketCategory(int port)
        {
            return port switch
            {
                80 or 443 => "Web Traffic",
                22 or 23 => "Remote Access",
                25 or 110 or 143 => "Email",
                >= 1024 => "High Port",
                _ => "Other"
            };
        }

        private string GetThreatExplanation(NetworkPacket packet, double score)
        {
            var reasons = new List<string>();

            if (Constants.SuspiciousPorts.Contains(packet.Port))
                reasons.Add($"Подозрительный порт {packet.Port}");

            if (packet.PacketSize > Constants.StandardPacketSize)
                reasons.Add($"Большой размер пакета ({packet.PacketSize} байт)");

            if (!Constants.StandardProtocols.Contains(packet.Protocol))
                reasons.Add($"Необычный протокол {packet.Protocol}");

            return reasons.Any()
                ? string.Join("; ", reasons)
                : "Нормальный трафик";
        }

        // Маппинг Entity -> DTO
        private PacketDto MapToDto(NetworkPacket packet)
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