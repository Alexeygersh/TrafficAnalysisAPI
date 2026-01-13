using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AuthorizedUser")]
    public class ClusteringController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IPythonMLService _pythonML;
        private readonly ILogger<ClusteringController> _logger;

        public ClusteringController(
            ApplicationDbContext context,
            IPythonMLService pythonML,
            ILogger<ClusteringController> logger)
        {
            _context = context;
            _pythonML = pythonML;
            _logger = logger;
        }

        // Получить метрики для конкретной сессии
        [HttpGet("source-metrics")]
        public async Task<ActionResult<IEnumerable<SourceMetrics>>> GetSourceMetrics(
        [FromQuery] int? sessionId = null)
        {
            var query = _context.SourceMetrics.AsQueryable();

            //if (!sessionId.HasValue)
            //{
            //    return BadRequest(new { message = "sessionId обязателен" });
            //}

            if (sessionId.HasValue)
            {
                query = query.Where(m => m.SessionId == sessionId.Value);
            }

            var metrics = await query
                .OrderByDescending(m => m.DangerScore)
                .ToListAsync();

            return Ok(metrics);
        }

        // Перерасчёт кластеров
        [HttpPost("recalculate")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<List<SourceClusterResultDto>>> RecalculateClusters(
            [FromQuery] string method = "kmeans",
            [FromQuery] int clusters = 3)
        {
            try
            {
                // Получаем текущие метрики
                var currentMetrics = await _context.SourceMetrics.ToListAsync();

                var metricsDto = currentMetrics.Select(m => new SourceMetricsDto
                {
                    SourceIP = m.SourceIP,
                    PacketCount = m.PacketCount,
                    PacketsPerSecond = m.PacketsPerSecond,
                    AveragePacketSize = m.AveragePacketSize,
                    TotalBytes = m.TotalBytes,
                    UniquePorts = m.UniquePorts,
                    Protocols = m.Protocols?.Split(',').ToList() ?? new List<string>()
                }).ToList();

                // Кластеризация
                var clusterResults = _pythonML.ClusterSources(metricsDto, method, clusters);

                // Обновление БД
                foreach (var result in clusterResults)
                {
                    var metric = currentMetrics.First(m => m.SourceIP == result.SourceIP);
                    metric.ClusterId = result.ClusterId;
                    metric.IsDangerous = result.IsDangerous;
                    metric.DangerScore = result.DangerScore;
                    metric.ClusterName = result.ClusterName;
                    metric.CalculatedAt = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync();

                return Ok(clusterResults);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error recalculating clusters");
                return StatusCode(500, new { message = "Ошибка перерасчёта кластеров" });
            }
        }

        // Пересчёт кластеров на основе ВСЕХ существующих пакетов в БД
        [HttpPost("recalculate-from-database")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<List<SourceClusterResultDto>>> RecalculateFromDatabase(
            [FromQuery] int? sessionId = null,
            [FromQuery] string method = "kmeans",
            [FromQuery] int clusters = 3)
        {
            try
            {
                // Получаем пакеты (все или из конкретной сессии)
                //var packetsQuery = _context.NetworkPackets.AsQueryable();

                //if (sessionId.HasValue)
                //{
                //    packetsQuery = packetsQuery.Where(p => p.SessionId == sessionId.Value);
                //}

                //var packets = await packetsQuery.ToListAsync();

                if (!sessionId.HasValue)
                {
                    return BadRequest(new { message = "sessionId обязателен для кластеризации" });
                }

                // Получаем пакеты ТОЛЬКО из указанной сессии
                var packets = await _context.NetworkPackets
                    .Where(p => p.SessionId == sessionId.Value)
                    .ToListAsync();

                if (!packets.Any())
                {
                    return BadRequest(new { message = "Нет пакетов для анализа" });
                }

                // Группировка по sourceIP для создания метрик
                var sourceGroups = packets
                    .GroupBy(p => p.SourceIP)
                    .Select(g => new
                    {
                        SourceIP = g.Key,
                        Packets = g.OrderBy(p => p.Timestamp).ToList()
                    })
                    .ToList();

                var metricsDto = new List<SourceMetricsDto>();

                foreach (var group in sourceGroups)
                {
                    if (group.Packets.Count < 2)
                    {
                        _logger.LogInformation($"Skipping {group.SourceIP}: only 1 packet");
                        continue;
                    }

                    var firstTime = group.Packets.First().Timestamp;
                    var lastTime = group.Packets.Last().Timestamp;
                    var duration = (lastTime - firstTime).TotalSeconds;

                    if (duration < 0.001) duration = 0.001;

                    var metric = new SourceMetricsDto
                    {
                        SourceIP = group.SourceIP,
                        PacketCount = group.Packets.Count,
                        PacketsPerSecond = (double)group.Packets.Count / duration,
                        AveragePacketSize = (double)group.Packets.Average(p => p.PacketSize),
                        TotalBytes = group.Packets.Sum(p => (long)p.PacketSize),
                        UniquePorts = group.Packets.Select(p => p.Port).Distinct().Count(),
                        Protocols = group.Packets.Select(p => p.Protocol).Distinct().ToList()
                    };

                    _logger.LogInformation($"Metric for {metric.SourceIP}: PPS={metric.PacketsPerSecond}, Count={metric.PacketCount}");

                    metricsDto.Add(metric);
                }

                // Кластеризация через Python
                var clusterResults = _pythonML.ClusterSources(metricsDto, method, clusters);

                // Удаляем старые метрики для этой сессии(если указана)
                /*
                if (sessionId.HasValue)
                {
                    var oldMetrics = await _context.SourceMetrics
                        .Where(m => packets.Select(p => p.SourceIP).Contains(m.SourceIP))
                        .ToListAsync();
                    _context.SourceMetrics.RemoveRange(oldMetrics);
                }
                else
                {
                    // Удаляем все старые метрики
                    var oldMetrics = await _context.SourceMetrics.ToListAsync();
                    _context.SourceMetrics.RemoveRange(oldMetrics);
                }
                */
                var oldMetrics = await _context.SourceMetrics
                    .Where(m => m.SessionId == sessionId.Value)
                    .ToListAsync();
                _context.SourceMetrics.RemoveRange(oldMetrics);

                // Сохранение новых метрик
                foreach (var result in clusterResults)
                {
                    var metric = new SourceMetrics
                    {
                        SessionId = sessionId.Value,
                        SourceIP = result.SourceIP,
                        PacketCount = result.PacketCount,
                        PacketsPerSecond = result.PacketsPerSecond,
                        AveragePacketSize = result.AveragePacketSize,
                        TotalBytes = result.TotalBytes,
                        ClusterId = result.ClusterId,
                        IsDangerous = result.IsDangerous,
                        DangerScore = result.DangerScore,
                        ClusterName = result.ClusterName,
                        UniquePorts = result.UniquePorts,
                        Protocols = string.Join(",", metricsDto
                            .First(m => m.SourceIP == result.SourceIP)
                            .Protocols),
                        CalculatedAt = DateTime.UtcNow
                    };

                    _context.SourceMetrics.Add(metric);
                }

                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    $"Recalculated clusters for session {sessionId.Value}: " +
                    $"{packets.Count} packets, {clusterResults.Count} sources"
                );

                return Ok(clusterResults);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error recalculating clusters from database");
                return StatusCode(500, new { message = "Ошибка перерасчёта кластеров", error = ex.Message });
            }
        }

        // Получить список сессий для фильтра
        [HttpGet("sessions")]
        public async Task<ActionResult<List<SessionFilterDto>>> GetSessions()
        {
            var sessions = await _context.TrafficSessions
                .Select(s => new SessionFilterDto
                {
                    Id = s.Id,
                    SessionName = s.SessionName,
                    PacketCount = s.Packets != null ? s.Packets.Count : 0
                })
                .OrderByDescending(s => s.Id)
                .ToListAsync();

            return Ok(sessions);
        }

        // DTO для сессий
        public class SessionFilterDto
        {
            public int Id { get; set; }
            public string SessionName { get; set; }
            public int PacketCount { get; set; }
        }

        // Информация о кластерах
        // Информация о кластерах для сессии
        [HttpGet("cluster-info")]
        public async Task<ActionResult<List<ClusterInfo>>> GetClusterInfo(
            [FromQuery] int? sessionId = null)
        {
            var query = _context.SourceMetrics.AsQueryable();

            //if (!sessionId.HasValue)
            //{
            //    return BadRequest(new { message = "sessionId обязателен" });
            //}

            if (sessionId.HasValue)
            {
                query = query.Where(m => m.SessionId == sessionId.Value);
            }

            var clusterInfo = await query
                .GroupBy(m => m.ClusterId)
                .Select(g => new ClusterInfo
                {
                    ClusterId = g.Key,
                    ClusterName = g.First().ClusterName,
                    IsDangerous = g.First().IsDangerous,
                    DangerScore = g.Average(m => m.DangerScore),
                    SourceCount = g.Count(),
                    AverageSpeed = g.Average(m => m.PacketsPerSecond),
                    MaxSpeed = g.Max(m => m.PacketsPerSecond)
                })
                .OrderByDescending(c => c.DangerScore)
                .ToListAsync();

            /*var clusterInfo = await _context.SourceMetrics
            .Where(m => m.SessionId == sessionId.Value)  // Фильтр
            .GroupBy(m => m.ClusterId)
            .Select(g => new ClusterInfo
            {
                ClusterId = g.Key,
                ClusterName = g.First().ClusterName,
                IsDangerous = g.First().IsDangerous,
                DangerScore = g.Average(m => m.DangerScore),
                SourceCount = g.Count(),
                AverageSpeed = g.Average(m => m.PacketsPerSecond),
                MaxSpeed = g.Max(m => m.PacketsPerSecond)
            })
            .OrderByDescending(c => c.DangerScore)
            .ToListAsync();*/

            return Ok(clusterInfo);
        }

        // Источники в кластере
        [HttpGet("cluster/{clusterId}/sources")]
        public async Task<ActionResult<List<SourceMetrics>>> GetClusterSources(int clusterId)
        {
            var sources = await _context.SourceMetrics
                .Where(m => m.ClusterId == clusterId)
                .OrderByDescending(m => m.PacketsPerSecond)
                .ToListAsync();

            if (!sources.Any())
                return NotFound(new { message = "Кластер не найден" });

            return Ok(sources);
        }



        // Визуализация кластеров (2D scatter)
        [HttpGet("visualize")]
        [ProducesResponseType(typeof(VisualizationResultDto), StatusCodes.Status200OK)]
        public async Task<ActionResult<VisualizationResultDto>> VisualizeCluster(
            [FromQuery] int sessionId)
        {
            try
            {
                var metrics = await _context.SourceMetrics
                    .Where(m => m.SessionId == sessionId)
                    .ToListAsync();

                if (!metrics.Any())
                    return NotFound(new { message = "Нет данных для визуализации" });

                var metricsData = metrics.Select(m => new
                {
                    sourceIP = m.SourceIP,
                    packetCount = m.PacketCount,
                    packetsPerSecond = m.PacketsPerSecond,
                    averagePacketSize = m.AveragePacketSize,
                    uniquePorts = m.UniquePorts,
                    clusterId = m.ClusterId,
                    isDangerous = m.IsDangerous,
                    dangerScore = m.DangerScore,
                    clusterName = m.ClusterName
                }).ToList();

                var visualization = _pythonML.VisualizeCluster(metricsData);

                if (!string.IsNullOrEmpty(visualization.Error))
                    return BadRequest(new { message = visualization.Error });

                return Ok(visualization);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating visualization");
                return StatusCode(500, new { message = "Ошибка создания визуализации" });
            }
        }
        /*
        // Heatmap характеристик кластеров
        [HttpGet("heatmap")]
        [ProducesResponseType(typeof(VisualizationResultDto), StatusCodes.Status200OK)]
        public async Task<ActionResult<VisualizationResultDto>> GetClusterHeatmap(
            [FromQuery] int sessionId)
        {
            try
            {
                var metrics = await _context.SourceMetrics
                    .Where(m => m.SessionId == sessionId)
                    .ToListAsync();

                if (!metrics.Any())
                    return NotFound(new { message = "Нет данных для heatmap" });

                var metricsData = metrics.Select(m => new
                {
                    sourceIP = m.SourceIP,
                    packetCount = m.PacketCount,
                    packetsPerSecond = m.PacketsPerSecond,
                    averagePacketSize = m.AveragePacketSize,
                    uniquePorts = m.UniquePorts,
                    clusterId = m.ClusterId,
                    isDangerous = m.IsDangerous,
                    dangerScore = m.DangerScore
                }).ToList();

                var heatmap = _pythonML.CreateClusterHeatmap(metricsData);

                if (!string.IsNullOrEmpty(heatmap.Error))
                    return BadRequest(new { message = heatmap.Error });

                return Ok(heatmap);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating heatmap");
                return StatusCode(500, new { message = "Ошибка создания heatmap" });
            }
        }

        // Timeline опасности
        [HttpGet("timeline")]
        [ProducesResponseType(typeof(VisualizationResultDto), StatusCodes.Status200OK)]
        public async Task<ActionResult<VisualizationResultDto>> GetDangerTimeline(
            [FromQuery] int sessionId)
        {
            try
            {
                var metrics = await _context.SourceMetrics
                    .Where(m => m.SessionId == sessionId)
                    .ToListAsync();

                if (!metrics.Any())
                    return NotFound(new { message = "Нет данных для timeline" });

                var metricsData = metrics.Select(m => new
                {
                    sourceIP = m.SourceIP,
                    packetCount = m.PacketCount,
                    packetsPerSecond = m.PacketsPerSecond,
                    clusterId = m.ClusterId,
                    isDangerous = m.IsDangerous,
                    dangerScore = m.DangerScore
                }).ToList();

                var timeline = _pythonML.CreateDangerTimeline(metricsData);

                if (!string.IsNullOrEmpty(timeline.Error))
                    return BadRequest(new { message = timeline.Error });

                return Ok(timeline);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating timeline");
                return StatusCode(500, new { message = "Ошибка создания timeline" });
            }
        }
        */
    }
}
