using Python.Runtime;
using System.Text.Json;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.DTOs.ML;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Services.Implementations
{
    public class PythonMLService : IPythonMLService
    {
        private readonly ILogger<PythonMLService> _logger;
        private readonly string _scriptsPath;
        private readonly string _modelPath;

        public PythonMLService(
            ILogger<PythonMLService> logger,
            IConfiguration configuration)
        {
            _logger = logger;
            _scriptsPath = configuration["PythonScripts:Path"] ??
                Path.Combine(Directory.GetCurrentDirectory(), "PythonScripts");

            // Путь к файлу модели — настраивается в appsettings.json
            // Пример: "PythonScripts:ModelPath": "PythonScripts/models/hybrid_ids_v1.pkl"
            _modelPath = configuration["PythonScripts:ModelPath"] ??
                Path.Combine(_scriptsPath, "models", "hybrid_ids_v1.pkl");
        }

        public List<ParsedPacketDto> ParseWiresharkCsv(string csvContent)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic parser = Py.Import("csv_parser");

                    dynamic result = parser.parse_wireshark_csv(csvContent);
                    string jsonResult = result?.ToString() ?? "[]";

                    var packets = JsonSerializer.Deserialize<List<ParsedPacketDto>>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    ) ?? new List<ParsedPacketDto>();

                    _logger.LogInformation($"Parsed {packets.Count} packets from CSV");
                    return packets;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in ParseWiresharkCsv");
                throw new Exception($"Failed to parse CSV: {ex.Message}");
            }
        }

        public List<SourceMetricsDto> CalculateSourceMetrics(List<ParsedPacketDto> packets)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic parser = Py.Import("csv_parser");

                    string packetsJson = JsonSerializer.Serialize(packets);
                    dynamic result = parser.calculate_session_metrics(packetsJson);
                    string jsonResult = result.ToString();

                    var metrics = JsonSerializer.Deserialize<List<SourceMetricsDto>>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    _logger.LogInformation($"Calculated metrics for {metrics.Count} sources");
                    return metrics;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in CalculateSourceMetrics");
                throw new Exception($"Failed to calculate metrics: {ex.Message}");
            }
        }

        public List<SourceClusterResultDto> ClusterSources(
            List<SourceMetricsDto> sources,
            string method = "kmeans",
            int nClusters = 3)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic clustering = Py.Import("clustering");

                    string sourcesJson = JsonSerializer.Serialize(sources);
                    _logger.LogInformation($"JSON sent to Python: {sourcesJson}");

                    dynamic result = clustering.cluster_sources(
                        sourcesJson, method, nClusters);
                    string jsonResult = result.ToString();

                    var clusterResults = JsonSerializer.Deserialize<List<SourceClusterResultDto>>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    _logger.LogInformation(
                        $"Clustered {clusterResults.Count} sources using {method}");
                    return clusterResults;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in ClusterSources");
                throw new Exception($"Failed to cluster sources: {ex.Message}");
            }
        }

        public PacketThreatResultDto CalculatePacketThreatScore(object packetData)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic scoring = Py.Import("threat_scoring");

                    string dataJson = JsonSerializer.Serialize(packetData);
                    dynamic result = scoring.calculate_packet_threat_score(dataJson);
                    string jsonResult = result.ToString();

                    return JsonSerializer.Deserialize<PacketThreatResultDto>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in CalculatePacketThreatScore");
                return new PacketThreatResultDto
                {
                    ThreatScore = 0.5,
                    ThreatLevel = "Medium",
                    IsMalicious = false,
                    Reasons = new List<string> { "Error in calculation" }
                };
            }
        }

        public Dictionary<int, PacketThreatResultDto> BatchScorePackets(List<object> packets)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic scoring = Py.Import("threat_scoring");

                    string packetsJson = JsonSerializer.Serialize(packets);
                    dynamic result = scoring.batch_score_packets(packetsJson);
                    string jsonResult = result.ToString();

                    var scores = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    var resultDict = new Dictionary<int, PacketThreatResultDto>();
                    foreach (var item in scores)
                    {
                        int packetId = Convert.ToInt32(item["packetId"]);
                        resultDict[packetId] = new PacketThreatResultDto
                        {
                            ThreatScore = Convert.ToDouble(item["threatScore"]),
                            ThreatLevel = item["threatLevel"].ToString(),
                            IsMalicious = Convert.ToBoolean(item["isMalicious"]),
                            Reasons = JsonSerializer.Deserialize<List<string>>(
                                item["reasons"].ToString())
                        };
                    }

                    _logger.LogInformation($"Scored {resultDict.Count} packets");
                    return resultDict;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in BatchScorePackets");
                return new Dictionary<int, PacketThreatResultDto>();
            }
        }

        public VisualizationResultDto VisualizeCluster(object clusterData)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic clustering = Py.Import("clustering");

                    string dataJson = JsonSerializer.Serialize(clusterData);
                    dynamic result = clustering.visualize_clusters(dataJson);
                    return JsonSerializer.Deserialize<VisualizationResultDto>(
                        result.ToString(),
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in VisualizeCluster");
                throw new Exception($"Failed to visualize cluster: {ex.Message}");
            }
        }

        public VisualizationResultDto CreateClusterHeatmap(object clusterData)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic clustering = Py.Import("clustering");

                    string dataJson = JsonSerializer.Serialize(clusterData);
                    dynamic result = clustering.create_cluster_heatmap(dataJson);
                    return JsonSerializer.Deserialize<VisualizationResultDto>(
                        result.ToString(),
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in CreateClusterHeatmap");
                throw new Exception($"Failed to create heatmap: {ex.Message}");
            }
        }

        public VisualizationResultDto CreateDangerTimeline(object clusterData)
        {
            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic clustering = Py.Import("clustering");

                    string dataJson = JsonSerializer.Serialize(clusterData);
                    dynamic result = clustering.create_danger_timeline(dataJson);
                    return JsonSerializer.Deserialize<VisualizationResultDto>(
                        result.ToString(),
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in CreateDangerTimeline");
                throw new Exception($"Failed to create timeline: {ex.Message}");
            }
        }

        // ---------------------------------------------------------------
        // Гибридная IDS — новый метод
        // ---------------------------------------------------------------

        /// <summary>
        /// Запускает HybridIDS (Random Forest + Isolation Forest) для списка
        /// IP-источников. Загружает модель из файла .pkl (один раз на запрос,
        /// Python кэширует модуль между вызовами через sys.modules).
        /// </summary>
        public List<SourceMLPredictionDto> PredictSourcesBatch(
            List<SourceMetricsDto> sources)
        {
            if (sources == null || sources.Count == 0)
                return new List<SourceMLPredictionDto>();

            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);

                    // Импортируем модуль hybrid_ids
                    dynamic hybridModule = Py.Import("hybrid_ids");

                    // Загружаем обученную модель из .pkl
                    // Python кэширует результат в глобальной переменной модуля
                    // чтобы не перечитывать файл на каждый запрос
                    dynamic model = hybridModule.HybridIDS.load(_modelPath);

                    // Формируем входной JSON: только нужные поля
                    var inputData = sources.Select(s => new
                    {
                        SourceIP = s.SourceIP,
                        PacketsPerSecond = s.PacketsPerSecond,
                        AveragePacketSize = s.AveragePacketSize,
                        UniquePorts = s.UniquePorts,
                        TotalBytes = (double)s.TotalBytes,
                        PacketCount = s.PacketCount,
                        // DangerScore берём из SourceMetricsDto — его там нет,
                        // поэтому передаём 0.0; при использовании SourceMetrics
                        // из БД нужно включить это поле в DTO
                        DangerScore = 0.0,
                    }).ToList();

                    string inputJson = JsonSerializer.Serialize(inputData);

                    // Вызываем batch-метод Python
                    dynamic resultPy = model.predict_batch(inputJson);
                    string resultJson = resultPy.ToString();

                    var predictions = JsonSerializer.Deserialize<List<SourceMLPredictionDto>>(
                        resultJson,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    ) ?? new List<SourceMLPredictionDto>();

                    _logger.LogInformation(
                        $"[HybridIDS] Предсказания получены: {predictions.Count} источников, " +
                        $"атак: {predictions.Count(p => p.IsAttack)}");

                    return predictions;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "[HybridIDS] Python error in PredictSourcesBatch");
                throw new Exception($"HybridIDS prediction failed: {ex.Message}");
            }
        }
    }
}


//using Python.Runtime;
//using TrafficAnalysisAPI.DTOs.ML;
//using TrafficAnalysisAPI.Services.Interfaces;

//namespace TrafficAnalysisAPI.Services.Implementations
//{
//    public class PythonMLService : IPythonMLService
//    {
//        private readonly ILogger<PythonMLService> _logger;

//        public PythonMLService(ILogger<PythonMLService> logger)
//        {
//            _logger = logger;
//        }

//        public PredictionResponseDto PredictPacket(PacketFeaturesDto features)
//        {
//            try
//            {
//                _logger.LogInformation("Predicting packet with Python.NET...");

//                using (Py.GIL()) // Захват GIL (важно!)
//                {
//                    // Импорт Python модуля
//                    dynamic py = Py.Import("hybrid_ids");

//                    // Получение загруженной модели
//                    dynamic model = py.HybridIDS.load();

//                    // Подготовка списка фичей
//                    var featuresList = new List<float>
//                    {
//                        features.FlowDuration,
//                        features.TotalFwdPackets,
//                        features.TotalBackwardPackets,
//                        features.FlowBytesPerSecond,
//                        features.FlowPacketsPerSecond,
//                        features.FwdPacketLengthMean,
//                        features.BwdPacketLengthMean,
//                        features.FlowIATMean,
//                        features.FlowIATStd,
//                        features.FwdIATMean,
//                        features.BwdIATMean,
//                        features.PshFlagCount,
//                        features.AckFlagCount,
//                        features.SynFlagCount,
//                        features.DestinationPort
//                    };

//                    // Вызов Python метода
//                    dynamic result = model.predict(featuresList.ToPyObject());

//                    // Парсинг результата
//                    bool isAttack = result["is_attack"].As<bool>();
//                    float confidence = result["confidence"].As<float>();
//                    string threatLevel = result["threat_level"].As<string>();
//                    string method = result["method"].As<string>();

//                    _logger.LogInformation($"Prediction: Attack={isAttack}, " +
//                                        $"Confidence={confidence:F2}, " +
//                                        $"Threat={threatLevel}");

//                    return new PredictionResponseDto
//                    {
//                        IsAttack = isAttack,
//                        Confidence = confidence,
//                        ThreatLevel = threatLevel,
//                        Method = method,
//                        Timestamp = DateTime.Now.ToString("o")
//                    };
//                }
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError(ex, "Error predicting packet with Python.NET");
//                // Fallback (если Python упал)
//                return new PredictionResponseDto
//                {
//                    IsAttack = false,
//                    Confidence = 0.5f,
//                    ThreatLevel = "Unknown",
//                    Method = "fallback",
//                    Timestamp = DateTime.Now.ToString("o")
//                };
//            }
//        }

//        public List<PredictionResponseDto> PredictBatch(List<PacketFeaturesDto> featuresList)
//        {
//            try
//            {
//                _logger.LogInformation($"Predicting batch of {featuresList.Count} packets...");

//                using (Py.GIL())
//                {
//                    dynamic py = Py.Import("hybrid_ids");
//                    dynamic model = py.HybridIDS.load();

//                    // Подготовка batch списка фичей
//                    var featuresListList = new List<List<float>>();
//                    foreach (var f in featuresList)
//                    {
//                        featuresListList.Add(new List<float>
//                        {
//                            f.FlowDuration,
//                            f.TotalFwdPackets,
//                            f.TotalBackwardPackets,
//                            f.FlowBytesPerSecond,
//                            f.FlowPacketsPerSecond,
//                            f.FwdPacketLengthMean,
//                            f.BwdPacketLengthMean,
//                            f.FlowIATMean,
//                            f.FlowIATStd,
//                            f.FwdIATMean,
//                            f.BwdIATMean,
//                            f.PshFlagCount,
//                            f.AckFlagCount,
//                            f.SynFlagCount,
//                            f.DestinationPort
//                        });
//                    }

//                    // Вызов Python метода batch
//                    dynamic result = model.predict_batch(featuresListList.ToPyObject());

//                    // Парсинг результатов
//                    var predictions = new List<PredictionResponseDto>();
//                    for (int i = 0; i < featuresList.Count; i++)
//                    {
//                        predictions.Add(new PredictionResponseDto
//                        {
//                            IsAttack = result["is_attack"][i].As<bool>(),
//                            Confidence = result["confidence"][i].As<float>(),
//                            ThreatLevel = result["threat_level"][i].As<string>(),
//                            Method = result["method"][i].As<string>(),
//                            Timestamp = DateTime.Now.ToString("o")
//                        });
//                    }

//                    _logger.LogInformation($"Batch prediction complete: {predictions.Count} predictions");
//                    return predictions;
//                }
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError(ex, "Error predicting batch with Python.NET");
//                return new List<PredictionResponseDto>(); // Fallback
//            }
//        }
//    }
//}