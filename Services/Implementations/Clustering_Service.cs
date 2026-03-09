//// Services/Implementations/ClusteringService.cs (обновление)
//using Python.Runtime;
//using TrafficAnalysisAPI.Services.Interfaces;

//namespace TrafficAnalysisAPI.Services.Implementations
//{
//    public class ClusteringService : IClusteringService
//    {
//        private readonly ILogger<ClusteringService> _logger;

//        public ClusteringService(ILogger<ClusteringService> logger)
//        {
//            _logger = logger;
//            InitializeClustering();
//        }

//        private void InitializeClustering()
//        {
//            try
//            {
//                _logger.LogInformation("Initializing optimized clustering...");

//                using (Py.GIL())
//                {
//                    // Загружаем оптимизированный модуль
//                    dynamic py = Py.Import("optimized_clustering");

//                    // Загружаем или создаем модель
//                    py.OptimizedClustering.load_or_create("models/clustering_model.pkl");

//                    _logger.LogInformation("✅ Optimized clustering initialized");
//                }
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError(ex, "Error initializing clustering");
//            }
//        }

//        public async Task<ClusteringResultDto> ClusterSessionAsync(int sessionId, string algorithm = 'kmeans')
//        {
//            _logger.LogInformation($"Clustering session {sessionId} with {algorithm}...");
//            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

//            try
//            {
//                // Не блокируем C# поток, выполняем в Task
//                var result = await Task.Run(() => DoClustering(sessionId, algorithm));

//                stopwatch.Stop();
//                _logger.LogInformation($"Clustering completed in {stopwatch.ElapsedMilliseconds}ms");

//                return result;
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError(ex, "Error clustering session");
//                throw;
//            }
//        }

//        private ClusteringResultDto DoClustering(int sessionId, string algorithm)
//        {
//            using (Py.GIL())  // Захватываем GIL только здесь
//            {
//                // Получаем пакеты из БД (через контекст)
//                var packets = GetPacketsFromDatabase(sessionId);

//                // Кластеризация (оптимизированная!)
//                dynamic py = Py.Import("optimized_clustering");
//                dynamic model = py.OptimizedClustering;

//                // Подготовка пакетов для Python
//                var packetsList = packets.Select(p => new
//                {
//                    id = p.Id,
//                    flowDuration = (float)p.FlowDuration,
//                    totalFwdPackets = p.TotalFwdPackets,
//                    totalBackwardPackets = p.TotalBackwardPackets,
//                    flowBytesPerSecond = (float)p.FlowBytesPerSecond,
//                    flowPacketsPerSecond = (float)p.FlowPacketsPerSecond,
//                    packetSize = (float)p.PacketSize,
//                    port = p.Port,
//                    protocol = p.Protocol
//                }).ToList();

//                // Вызов оптимизированной кластеризации
//                dynamic results = model.cluster_packets(packetsList.ToPyObject(), algorithm);

//                // Парсинг результатов
//                var clusteringResults = new List<PacketClusterDto>();
//                for (int i = 0; i < len(results); i++)
//                {
//                    clusteringResults.Add(new PacketClusterDto
//                    {
//                        PacketId = results[i]["packetId"],
//                        ClusterId = results[i]["clusterId"],
//                        DangerScore = results[i]["dangerScore"],
//                        IsDangerous = results[i]["isDangerous"]
//                    });
//                }

//                // Сохранение в БД
//                SaveClusteringResults(clusteringResults);

//                return new ClusteringResultDto
//                {
//                    SessionId = sessionId,
//                    Algorithm = algorithm,
//                    TotalPackets = packets.Count,
//                    ClustersCount = clusteringResults.Select(r => r.ClusterId).Distinct().Count(),
//                    DangerousCount = clusteringResults.Count(r => r.IsDangerous),
//                    Packets = clusteringResults
//                };
//            }
//        }
//    }
//}