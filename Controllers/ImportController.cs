using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
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
        private readonly ILogger<ImportController> _logger;

        public ImportController(
            ApplicationDbContext context,
            IPythonMLService pythonML,
            ILogger<ImportController> logger)
        {
            _context = context;
            _pythonML = pythonML;
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
