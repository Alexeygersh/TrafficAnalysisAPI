using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;
using TrafficAnalysisAPI.Services.Implementations;
using System.Diagnostics;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AdminOnly")]
    public class ImportController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IPythonMLService _pythonML;
        private readonly ILogger<ImportController> _logger;
        private readonly IPcapParserService _pcapParser;

        public ImportController(
            ApplicationDbContext context,
            IPythonMLService pythonML,
            IPcapParserService pcapParser,       // <-- новое
            ILogger<ImportController> logger)
        {
            _context = context;
            _pythonML = pythonML;
            _pcapParser = pcapParser;             // <-- новое
            _logger = logger;
        }

        [HttpPost("csv")]
        [ProducesResponseType(typeof(ImportResultDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<ImportResultDto>> ImportCsv(
            IFormFile file,
            [FromForm] int? sessionId)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "Файл не выбран" });

            if (!file.FileName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                return BadRequest(new { message = "Только CSV файлы поддерживаются" });

            try
            {
                // Чтение CSV
                //string csvContent;
                //using (var reader = new StreamReader(file.OpenReadStream()))
                //{
                //    csvContent = await reader.ReadToEndAsync();
                //}

                // Чтение CSV с автоопределением кодировки
                string csvContent;
                using (var stream = file.OpenReadStream())
                {
                    // Пробуем UTF-8 с BOM сначала
                    if (HasUtf8Bom(stream))
                    {
                        stream.Position = 0;
                        using (var reader = new StreamReader(stream, new UTF8Encoding(true)))
                        {
                            csvContent = await reader.ReadToEndAsync();
                        }
                    }
                    else
                    {
                        // Пробуем Windows-1251 (кириллица) → UTF-8
                        stream.Position = 0;
                        using (var reader1251 = new StreamReader(stream, Encoding.GetEncoding(1251)))
                        {
                            string content1251 = await reader1251.ReadToEndAsync();
                            csvContent = Encoding.UTF8.GetString(Encoding.GetEncoding(1251).GetBytes(content1251));
                        }
                    }
                }

                static bool HasUtf8Bom(Stream stream)
                {
                    var bom = new byte[3];
                    if (stream.Length >= 3 && stream.Read(bom, 0, 3) == 3)
                    {
                        stream.Position = 0;
                        return bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF;
                    }
                    stream.Position = 0;
                    return false;
                }


                /*
                string csvContent;
                using (var stream = file.OpenReadStream())
                {
                    // Пробуем определить кодировку
                    using (var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true))
                    {
                        csvContent = await reader.ReadToEndAsync();
                    }
                }

                // Проверка: если содержит кириллицу, но декодировано неправильно
                if (csvContent.Contains("�")) // Символ замены (replacement character)
                {
                    _logger.LogWarning("Detected encoding issues, retrying with Windows-1251");

                    using (var stream = file.OpenReadStream())
                    {
                        // Пробуем Windows-1251 (кириллица Windows)
                        using (var reader = new StreamReader(stream, System.Text.Encoding.GetEncoding(1251)))
                        {
                            csvContent = await reader.ReadToEndAsync();
                        }
                    }
                }

                _logger.LogInformation($"CSV content length: {csvContent.Length} chars");
                // ... остальной код без изменений
                */

                // Парсинг через Python
                var parsedPackets = _pythonML.ParseWiresharkCsv(csvContent);

                if (parsedPackets.Count == 0)
                    return BadRequest(new { message = "Не удалось распарсить пакеты" });

                // Создание сессии , если не указана
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
                        SessionName = $"Import {DateTime.Now:yyyy-MM-dd HH:mm}",
                        Description = $"Imported from {file.FileName}",
                        StartTime = DateTime.UtcNow
                    };
                    _context.TrafficSessions.Add(session);
                    await _context.SaveChangesAsync();
                }
                // Импорт пакетов в БД
                int imported = 0;
                foreach (var parsed in parsedPackets)
                {
                    var packet = new NetworkPacket
                    {
                        SourceIP = parsed.SourceIP,
                        DestinationIP = parsed.DestinationIP,
                        Port = parsed.Port,
                        Protocol = parsed.Protocol,
                        PacketSize = parsed.Length,
                        Timestamp = session.StartTime.AddSeconds(parsed.Time),
                        SessionId = session.Id
                    };

                    _context.NetworkPackets.Add(packet);
                    imported++;
                }

                await _context.SaveChangesAsync();

                // Расчёт метрик источников
                var sourceMetrics = _pythonML.CalculateSourceMetrics(parsedPackets);

                // Кластеризация
                var clusterResults = _pythonML.ClusterSources(sourceMetrics);

                // Сохранение метрик
                foreach (var result in clusterResults)
                {
                    var metric = new SourceMetrics
                    {
                        SourceIP = result.SourceIP,
                        PacketCount = result.PacketCount,
                        PacketsPerSecond = result.PacketsPerSecond,
                        AveragePacketSize = result.AveragePacketSize,
                        TotalBytes = result.TotalBytes,
                        ClusterId = result.ClusterId,
                        IsDangerous = result.IsDangerous,
                        DangerScore = result.DangerScore,
                        ClusterName = result.ClusterName,
                        UniquePorts = result.UniquePorts
                    };

                    _context.SourceMetrics.Add(metric);
                }

                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    $"Imported {imported} packets, created {clusterResults.Count} source metrics"
                );

                return Ok(new ImportResultDto
                {
                    ImportedPackets = imported,
                    SessionId = session.Id,
                    SessionName = session.SessionName,
                    SourcesAnalyzed = clusterResults.Count,
                    DangerousSources = clusterResults.Count(r => r.IsDangerous),
                    Clusters = clusterResults.Select(r => r.ClusterId).Distinct().Count()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error importing CSV");
                return StatusCode(500, new { message = "Ошибка импорта", error = ex.Message });
            }
        }

        /// <summary>
        /// POST /api/import/pcap
        /// Импорт .pcap файла: парсинг → построение flows → сохранение в FlowMetrics.
        /// </summary>
        [HttpPost("pcap")]
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

            // 1. Сохраняем временный файл (SharpPcap читает с диска)
            var tempPath = Path.Combine(Path.GetTempPath(),
                $"pcap_import_{Guid.NewGuid()}.pcap");

            try
            {
                using (var stream = System.IO.File.Create(tempPath))
                    await file.CopyToAsync(stream);

                _logger.LogInformation(
                    $"[ImportPcap] Saved to temp: {tempPath}, size={file.Length}");

                // 2. Парсим .pcap в список RawPacket
                var rawPackets = _pcapParser.ParsePcapFile(tempPath);

                if (rawPackets.Count == 0)
                    return BadRequest(new { message = "Файл не содержит IP-пакетов" });

                // 3. Создаём или находим сессию
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

                // 4. Строим flows через Python
                var flows = _pythonML.BuildFlowsFromPackets(rawPackets);

                if (flows.Count == 0)
                    return BadRequest(new { message = "Не удалось построить flows" });

                // 5. Сохраняем в FlowMetrics
                var sessionStartUtc = session.StartTime;
                var firstPacketTs = rawPackets.Min(p => p.TimestampSec);

                foreach (var f in flows)
                {
                    // Конвертируем Unix-timestamp в UTC DateTime
                    var startDt = DateTimeOffset.FromUnixTimeMilliseconds(
                        (long)(f.FlowStartTime * 1000)).UtcDateTime;
                    var endDt = DateTimeOffset.FromUnixTimeMilliseconds(
                        (long)(f.FlowEndTime * 1000)).UtcDateTime;

                    var entity = new FlowMetrics
                    {
                        SessionId = session.Id,
                        SourceIP = f.SourceIP,
                        DestinationIP = f.DestinationIP,
                        SourcePort = f.SourcePort,
                        DestinationPort = f.DestinationPort,
                        Protocol = f.Protocol ?? "",
                        FlowStartTime = startDt,
                        FlowEndTime = endDt,

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
                    _context.FlowMetrics.Add(entity);
                }

                await _context.SaveChangesAsync();

                stopwatch.Stop();

                // Статистика по протоколам для ответа
                var protoStats = flows
                    .GroupBy(f => f.Protocol ?? "UNKNOWN")
                    .ToDictionary(g => g.Key, g => g.Count());

                _logger.LogInformation(
                    $"[ImportPcap] Done: {rawPackets.Count} packets → {flows.Count} flows, " +
                    $"elapsed={stopwatch.ElapsedMilliseconds}ms");

                return Ok(new PcapImportResultDto
                {
                    SessionId = session.Id,
                    SessionName = session.SessionName,
                    RawPacketsParsed = rawPackets.Count,
                    FlowsBuilt = flows.Count,
                    FlowsSavedToDb = flows.Count,
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

    }

    public class ImportResultDto
    {
        public int ImportedPackets { get; set; }
        public int SessionId { get; set; }
        public string SessionName { get; set; }
        public int SourcesAnalyzed { get; set; }
        public int DangerousSources { get; set; }
        public int Clusters { get; set; }
    }
}
