using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Implementations;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AdminOnly")]
    public class ImportController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IPythonMLService _pythonML;
        private readonly IPcapParserService _pcapParser;
        private readonly ILogger<ImportController> _logger;

        public ImportController(
            ApplicationDbContext context,
            IPythonMLService pythonML,
            IPcapParserService pcapParser,
            ILogger<ImportController> logger)
        {
            _context = context;
            _pythonML = pythonML;
            _pcapParser = pcapParser;
            _logger = logger;
        }

        /// <summary>
        /// POST /api/import/pcap
        /// Импорт .pcap файла:
        ///   1. Парсинг → List&lt;RawPacket&gt;
        ///   2. Построение flows через Python → List&lt;FlowFeaturesDto&gt;
        ///   3. Сохранение пакетов в NetworkPackets (id присваиваются БД)
        ///   4. Сохранение flows в FlowMetrics (id присваиваются БД)
        ///   5. Связывание: на каждый flow → UPDATE NetworkPackets SET FlowId = :id
        ///      WHERE id IN (packet_indices_для_этого_flow)
        /// </summary>
        [HttpPost("pcap")]
        [RequestSizeLimit(2L * 1024 * 1024 * 1024)]                  // 2 GB
        [RequestFormLimits(MultipartBodyLengthLimit = 2L * 1024 * 1024 * 1024)]
        [ProducesResponseType(typeof(PcapImportResultDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<PcapImportResultDto>> ImportPcap(
            IFormFile file,
            [FromForm] int? sessionId = null)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "Файл не загружен" });

            if (!file.FileName.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
             && !file.FileName.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
                return BadRequest(new { message = "Ожидается .pcap или .pcapng" });

            var stopwatch = Stopwatch.StartNew();

            var tempPath = Path.Combine(Path.GetTempPath(),
                $"pcap_import_{Guid.NewGuid()}.pcap");

            try
            {
                // === 1. Сохранение во временный файл ===
                using (var stream = System.IO.File.Create(tempPath))
                    await file.CopyToAsync(stream);

                _logger.LogInformation(
                    $"[ImportPcap] Saved to temp: {tempPath}, size={file.Length}");

                // === 2. Парсинг .pcap ===
                var rawPackets = _pcapParser.ParsePcapFile(tempPath);

                if (rawPackets.Count == 0)
                    return BadRequest(new { message = "Файл не содержит IP-пакетов" });

                // === 3. Сессия ===
                TrafficSession session;
                if (sessionId.HasValue)
                {
                    session = await _context.TrafficSessions.FindAsync(sessionId.Value);
                    if (session == null)
                        return NotFound(new { message = "Сессия не найдена" });
                }
                else
                {
                    session = new TrafficSession
                    {
                        SessionName = $"PCAP {DateTime.Now:yyyy-MM-dd HH:mm}",
                        Description = $"Imported from {file.FileName} ({rawPackets.Count} pkts)",
                        StartTime = DateTime.UtcNow
                    };
                    _context.TrafficSessions.Add(session);
                    await _context.SaveChangesAsync();
                }

                // === 4. Построение flows через Python ===
                var flows = _pythonML.BuildFlowsFromPackets(rawPackets);

                if (flows.Count == 0)
                    return BadRequest(new { message = "Не удалось построить flows" });

                // === 5. Сохранение пакетов ===
                // Важно: сохраняем пакеты в ТОМ ЖЕ ПОРЯДКЕ что и в rawPackets,
                // чтобы позиция [i] в savedPackets соответствовала позиции [i]
                // в rawPackets. Потом Python-индексы PacketIndices ссылаются на эти позиции.
                var savedPackets = new List<NetworkPacket>(rawPackets.Count);
                foreach (var raw in rawPackets)
                {
                    var packet = new NetworkPacket
                    {
                        SourceIP = raw.SourceIP,
                        DestinationIP = raw.DestinationIP,
                        Port = raw.DestinationPort,  // используем DestinationPort как "порт"
                        Protocol = raw.Protocol,
                        PacketSize = raw.PacketSize,
                        Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(
                            (long)(raw.TimestampSec * 1000)).UtcDateTime,
                        SessionId = session.Id,
                        FlowId = null,  // проставим ниже
                    };
                    savedPackets.Add(packet);
                }
                _context.NetworkPackets.AddRange(savedPackets);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    $"[ImportPcap] Saved {savedPackets.Count} packets to DB");

                // === 6. Сохранение flows ===
                var savedFlows = new List<FlowMetrics>(flows.Count);
                foreach (var f in flows)
                {
                    var flow = MapFlowDtoToEntity(f, session.Id);
                    savedFlows.Add(flow);
                }
                _context.FlowMetrics.AddRange(savedFlows);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    $"[ImportPcap] Saved {savedFlows.Count} flows to DB");

                // === 7. Связывание пакетов с flows через PacketIndices ===
                int linkedPackets = 0;
                for (int i = 0; i < flows.Count; i++)
                {
                    var flowDto = flows[i];
                    var flowEntity = savedFlows[i];

                    if (flowDto.PacketIndices == null || flowDto.PacketIndices.Count == 0)
                        continue;

                    foreach (var idx in flowDto.PacketIndices)
                    {
                        if (idx < 0 || idx >= savedPackets.Count) continue;
                        savedPackets[idx].FlowId = flowEntity.Id;
                        linkedPackets++;
                    }
                }
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    $"[ImportPcap] Linked {linkedPackets} packets to flows");

                // === 8. Статистика по протоколам ===
                var protoStats = rawPackets
                    .GroupBy(p => p.Protocol ?? "UNKNOWN")
                    .ToDictionary(g => g.Key, g => g.Count());

                _logger.LogInformation(
                    $"[ImportPcap] Done: {rawPackets.Count} packets → {flows.Count} flows, " +
                    $"linked={linkedPackets}, elapsed={stopwatch.ElapsedMilliseconds}ms");

                return Ok(new PcapImportResultDto
                {
                    SessionId = session.Id,
                    SessionName = session.SessionName,
                    RawPacketsParsed = rawPackets.Count,
                    FlowsBuilt = flows.Count,
                    FlowsSavedToDb = savedFlows.Count,
                    PacketsSavedToDb = savedPackets.Count,
                    PacketsLinkedToFlows = linkedPackets,
                    ProtocolStats = protoStats,
                    ElapsedMs = stopwatch.ElapsedMilliseconds,
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[ImportPcap] Error");
                return StatusCode(500, new
                {
                    message = "Ошибка импорта PCAP",
                    error = ex.Message
                });
            }
            finally
            {
                if (System.IO.File.Exists(tempPath))
                {
                    try { System.IO.File.Delete(tempPath); } catch { }
                }
            }
        }

        /// <summary>
        /// Маппинг из FlowFeaturesDto (приходит от Python) в FlowMetrics (Entity для БД).
        /// Все ~78 полей переносятся 1:1 по имени.
        /// </summary>
        private FlowMetrics MapFlowDtoToEntity(FlowFeaturesDto f, int sessionId)
        {
            return new FlowMetrics
            {
                SessionId = sessionId,
                SourceIP = f.SourceIP,
                DestinationIP = f.DestinationIP,
                SourcePort = f.SourcePort,
                DestinationPort = f.DestinationPort,
                Protocol = f.Protocol,
                FlowStartTime = DateTimeOffset.FromUnixTimeMilliseconds(
                    (long)(f.FlowStartTime * 1000)).UtcDateTime,
                FlowEndTime = DateTimeOffset.FromUnixTimeMilliseconds(
                    (long)(f.FlowEndTime * 1000)).UtcDateTime,

                FlowDuration = f.FlowDuration,
                TotalFwdPackets = f.TotalFwdPackets,
                TotalBackwardPackets = f.TotalBackwardPackets,
                TotalLengthFwdPackets = f.TotalLengthFwdPackets,
                TotalLengthBwdPackets = f.TotalLengthBwdPackets,

                FwdPacketLengthMax = f.FwdPacketLengthMax,
                FwdPacketLengthMin = f.FwdPacketLengthMin,
                FwdPacketLengthMean = f.FwdPacketLengthMean,
                FwdPacketLengthStd = f.FwdPacketLengthStd,

                BwdPacketLengthMax = f.BwdPacketLengthMax,
                BwdPacketLengthMin = f.BwdPacketLengthMin,
                BwdPacketLengthMean = f.BwdPacketLengthMean,
                BwdPacketLengthStd = f.BwdPacketLengthStd,

                FlowBytesPerSec = f.FlowBytesPerSec,
                FlowPacketsPerSec = f.FlowPacketsPerSec,
                FwdPacketsPerSec = f.FwdPacketsPerSec,
                BwdPacketsPerSec = f.BwdPacketsPerSec,

                FlowIATMean = f.FlowIATMean,
                FlowIATStd = f.FlowIATStd,
                FlowIATMax = f.FlowIATMax,
                FlowIATMin = f.FlowIATMin,
                FwdIATTotal = f.FwdIATTotal,
                FwdIATMean = f.FwdIATMean,
                FwdIATStd = f.FwdIATStd,
                FwdIATMax = f.FwdIATMax,
                FwdIATMin = f.FwdIATMin,
                BwdIATTotal = f.BwdIATTotal,
                BwdIATMean = f.BwdIATMean,
                BwdIATStd = f.BwdIATStd,
                BwdIATMax = f.BwdIATMax,
                BwdIATMin = f.BwdIATMin,

                FwdPSHFlags = f.FwdPSHFlags,
                BwdPSHFlags = f.BwdPSHFlags,
                FwdURGFlags = f.FwdURGFlags,
                BwdURGFlags = f.BwdURGFlags,
                FINFlagCount = f.FINFlagCount,
                SYNFlagCount = f.SYNFlagCount,
                RSTFlagCount = f.RSTFlagCount,
                PSHFlagCount = f.PSHFlagCount,
                ACKFlagCount = f.ACKFlagCount,
                URGFlagCount = f.URGFlagCount,
                CWEFlagCount = f.CWEFlagCount,
                ECEFlagCount = f.ECEFlagCount,

                FwdHeaderLength = f.FwdHeaderLength,
                BwdHeaderLength = f.BwdHeaderLength,
                MinSegSizeForward = f.MinSegSizeForward,

                MinPacketLength = f.MinPacketLength,
                MaxPacketLength = f.MaxPacketLength,
                PacketLengthMean = f.PacketLengthMean,
                PacketLengthStd = f.PacketLengthStd,
                PacketLengthVariance = f.PacketLengthVariance,

                AveragePacketSize = f.AveragePacketSize,
                AvgFwdSegmentSize = f.AvgFwdSegmentSize,
                AvgBwdSegmentSize = f.AvgBwdSegmentSize,
                DownUpRatio = f.DownUpRatio,

                InitWinBytesForward = f.InitWinBytesForward,
                InitWinBytesBackward = f.InitWinBytesBackward,
                ActDataPktFwd = f.ActDataPktFwd,

                FwdAvgBytesBulk = f.FwdAvgBytesBulk,
                FwdAvgPacketsBulk = f.FwdAvgPacketsBulk,
                FwdAvgBulkRate = f.FwdAvgBulkRate,
                BwdAvgBytesBulk = f.BwdAvgBytesBulk,
                BwdAvgPacketsBulk = f.BwdAvgPacketsBulk,
                BwdAvgBulkRate = f.BwdAvgBulkRate,

                SubflowFwdPackets = f.SubflowFwdPackets,
                SubflowFwdBytes = f.SubflowFwdBytes,
                SubflowBwdPackets = f.SubflowBwdPackets,
                SubflowBwdBytes = f.SubflowBwdBytes,

                ActiveMean = f.ActiveMean,
                ActiveStd = f.ActiveStd,
                ActiveMax = f.ActiveMax,
                ActiveMin = f.ActiveMin,
                IdleMean = f.IdleMean,
                IdleStd = f.IdleStd,
                IdleMax = f.IdleMax,
                IdleMin = f.IdleMin,
            };
        }
    }
}
