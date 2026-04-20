using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TrafficAnalysisAPI.Services.Implementations;

namespace TrafficAnalysisAPI.Controllers
{
    /// <summary>
    /// ВРЕМЕННЫЙ контроллер для проверки парсера .pcap.
    /// Удалить/отключить после того как убедимся что SharpPcap работает корректно.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AdminOnly")]
    public class PcapTestController : ControllerBase
    {
        private readonly IPcapParserService _parser;
        private readonly ILogger<PcapTestController> _logger;

        public PcapTestController(IPcapParserService parser, ILogger<PcapTestController> logger)
        {
            _parser = parser;
            _logger = logger;
        }

        /// <summary>
        /// POST /api/pcaptest/parse
        /// Принимает .pcap файл, парсит и возвращает статистику.
        /// НЕ сохраняет в БД — только диагностика.
        /// </summary>
        [HttpPost("parse")]
        public async Task<IActionResult> ParsePcap(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "Файл не загружен" });

            if (!file.FileName.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
             && !file.FileName.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
                return BadRequest(new { message = "Ожидается .pcap или .pcapng" });

            // Сохраняем временный файл (SharpPcap читает только с диска)
            var tempPath = Path.Combine(Path.GetTempPath(),
                $"pcap_test_{Guid.NewGuid()}.pcap");

            try
            {
                using (var stream = System.IO.File.Create(tempPath))
                    await file.CopyToAsync(stream);

                _logger.LogInformation($"[PcapTest] Saved to temp: {tempPath}, size={file.Length}");

                var packets = _parser.ParsePcapFile(tempPath);

                // Собираем статистику
                var protocolStats = packets
                    .GroupBy(p => p.Protocol)
                    .Select(g => new { protocol = g.Key, count = g.Count() })
                    .OrderByDescending(x => x.count)
                    .ToList();

                var sourceIpStats = packets
                    .GroupBy(p => p.SourceIP)
                    .Select(g => new { sourceIP = g.Key, count = g.Count() })
                    .OrderByDescending(x => x.count)
                    .Take(10)
                    .ToList();

                int tcpWithPsh = packets.Count(p => p.Protocol == "TCP" && p.FlagPSH);
                int tcpWithSyn = packets.Count(p => p.Protocol == "TCP" && p.FlagSYN);

                return Ok(new
                {
                    totalPackets = packets.Count,
                    protocols = protocolStats,
                    top10Sources = sourceIpStats,
                    tcpStats = new
                    {
                        totalTcp = packets.Count(p => p.Protocol == "TCP"),
                        withPshFlag = tcpWithPsh,
                        withSynFlag = tcpWithSyn,
                    },
                    sample = packets.Take(3).ToList(), // первые 3 пакета целиком для проверки полей
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PcapTest] Parse failed");
                return StatusCode(500, new { message = "Ошибка парсинга", error = ex.Message });
            }
            finally
            {
                if (System.IO.File.Exists(tempPath))
                {
                    try { System.IO.File.Delete(tempPath); } catch { /* ignore */ }
                }
            }
        }
    }
}
