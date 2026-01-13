using Python.Runtime;
using System.Text.Json;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Services.Implementations
{
    public class PythonMLService : IPythonMLService
    {
        private readonly ILogger<PythonMLService> _logger;
        private readonly string _scriptsPath;

        public PythonMLService(
            ILogger<PythonMLService> logger,
            IConfiguration configuration)
        {
            _logger = logger;
            _scriptsPath = configuration["PythonScripts:Path"] ??
                Path.Combine(Directory.GetCurrentDirectory(), "PythonScripts");
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
                    //string jsonResult = result.ToString();
                    string jsonResult = result?.ToString() ?? "[]";

                    //var packets = JsonSerializer.Deserialize<List<ParsedPacketDto>>(
                    //   jsonResult,
                    //    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    //);
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
                        sourcesJson,
                        method,
                        nClusters
                    );
                    string jsonResult = result.ToString();

                    var clusterResults = JsonSerializer.Deserialize<List<SourceClusterResultDto>>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    _logger.LogInformation(
                        $"Clustered {clusterResults.Count} sources using {method}"
                    );

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

                    var threatResult = JsonSerializer.Deserialize<PacketThreatResultDto>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    return threatResult;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in CalculatePacketThreatScore");

                // Возвращаем дефолтное значение при ошибке
                return new PacketThreatResultDto
                {
                    ThreatScore = 0.5,
                    ThreatLevel = "Medium",
                    IsMalicious = false,
                    Reasons = new List<string> { "Error in calculation" }
                };
            }
        }

        public Dictionary<int, PacketThreatResultDto> BatchScorePackets(
            List<object> packets)
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
                                item["reasons"].ToString()
                            )
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
                    string jsonResult = result.ToString();

                    var visualization = JsonSerializer.Deserialize<VisualizationResultDto>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    _logger.LogInformation("Cluster visualization created successfully");

                    return visualization;
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
                    string jsonResult = result.ToString();

                    return JsonSerializer.Deserialize<VisualizationResultDto>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );
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
                    string jsonResult = result.ToString();

                    return JsonSerializer.Deserialize<VisualizationResultDto>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "Python error in CreateDangerTimeline");
                throw new Exception($"Failed to create timeline: {ex.Message}");
            }
        }
    }
}