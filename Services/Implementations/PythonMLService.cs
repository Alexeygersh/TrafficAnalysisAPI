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
        private readonly string _modelV2Path;
        private readonly string _catBoostModelPath;

        public PythonMLService(
            ILogger<PythonMLService> logger,
            IConfiguration configuration)
        {
            _logger = logger;

            _scriptsPath = configuration["PythonScripts:Path"]
                ?? Path.Combine(Directory.GetCurrentDirectory(), "PythonScripts");

            _modelV2Path = configuration["PythonScripts:ModelV2Path"]
                ?? Path.Combine(_scriptsPath, "models", "hybrid_ids_v2.pkl");

            _catBoostModelPath = configuration["PythonScripts:CatBoostModelPath"]
                ?? Path.Combine(_scriptsPath, "models", "catboost_ids_v2.pkl");
        }

        // ============================================================
        //  BUILD FLOWS FROM PACKETS
        // ============================================================
        public List<FlowFeaturesDto> BuildFlowsFromPackets(List<RawPacket> packets)
        {
            if (packets == null || packets.Count == 0)
                return new List<FlowFeaturesDto>();

            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);

                    dynamic flowModule = Py.Import("flow_features");

                    string packetsJson = JsonSerializer.Serialize(packets);
                    _logger.LogInformation(
                        $"[FlowFeatures] Sending {packets.Count} packets to Python");

                    dynamic result = flowModule.build_flows_from_packets(packetsJson);
                    string jsonResult = result?.ToString() ?? "[]";

                    var flows = JsonSerializer.Deserialize<List<FlowFeaturesDto>>(
                        jsonResult,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    ) ?? new List<FlowFeaturesDto>();

                    _logger.LogInformation(
                        $"[FlowFeatures] Built {flows.Count} flows from {packets.Count} packets");

                    return flows;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "[FlowFeatures] Python error in BuildFlowsFromPackets");
                throw new Exception($"Failed to build flows: {ex.Message}");
            }
        }

        // ============================================================
        //  PREDICT FLOWS BATCH (RF или CatBoost)
        // ============================================================
        public List<FlowMLPredictionDto> PredictFlowsBatch(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            string modelType = "rf")
        {
            if (flows == null || flows.Count == 0)
                return new List<FlowMLPredictionDto>();

            // Определяем какой модуль и файл использовать
            string pyModuleName, pyClassName, pklPath;
            if (modelType?.ToLower() == "catboost")
            {
                pyModuleName = "catboost_ids";
                pyClassName = "CatBoostIDS";
                pklPath = _catBoostModelPath;
            }
            else
            {
                pyModuleName = "hybrid_ids";
                pyClassName = "HybridIDS";
                pklPath = _modelV2Path;
            }

            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);

                    dynamic module = Py.Import(pyModuleName);
                    dynamic modelClass = module.GetAttr(pyClassName);
                    dynamic model = modelClass.load(pklPath);

                    var jsonOptions = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = null,
                        ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles,
                    };
                    string flowsJson = JsonSerializer.Serialize(flows, jsonOptions);

                    _logger.LogInformation(
                        $"[FlowML-{modelType}] Отправка {flows.Count} flows");

                    dynamic resultPy = model.predict_batch(flowsJson);
                    string resultJson = resultPy?.ToString() ?? "[]";

                    var rawList = JsonSerializer.Deserialize<List<FlowMLPredictionDto>>(
                        resultJson,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    ) ?? new List<FlowMLPredictionDto>();

                    // Заполняем FlowId по порядку
                    for (int i = 0; i < rawList.Count && i < flows.Count; i++)
                    {
                        rawList[i].FlowId = flows[i].Id;
                    }

                    _logger.LogInformation(
                        $"[FlowML-{modelType}] Получено {rawList.Count} предсказаний");
                    return rawList;
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, $"[FlowML-{modelType}] Python error");
                throw new Exception(
                    $"ML prediction failed ({modelType}): {ex.Message}. " +
                    "Проверьте что соответствующая модель обучена.");
            }
        }

        // ============================================================
        //  FIND SIMILAR FLOWS (режим 1, Этап 6)
        // ============================================================
        public string FindSimilarFlows(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            int targetFlowId,
            double w1, double w2, double w3,
            int k = 10)
        {
            if (flows == null || flows.Count == 0)
                return "{\"error\":\"Empty flows\",\"results\":[]}";

            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);

                    dynamic simModule = Py.Import("similarity");

                    var jsonOptions = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = null,
                        ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles,
                    };
                    string flowsJson = JsonSerializer.Serialize(flows, jsonOptions);

                    _logger.LogInformation(
                        $"[Similarity] Finding similar to flow #{targetFlowId} " +
                        $"in {flows.Count} flows (w1={w1}, w2={w2}, w3={w3}, k={k})");

                    dynamic resultPy = simModule.find_similar_flows(
                        flowsJson, targetFlowId, w1, w2, w3, k);
                    return resultPy?.ToString() ?? "{\"results\":[]}";
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "[Similarity] Python error in FindSimilarFlows");
                throw new Exception($"Similarity calculation failed: {ex.Message}");
            }
        }

        // ============================================================
        //  kNN CLASSIFY (режим 2, Этап 6)
        // ============================================================
        public string KnnClassifyFlows(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            Dictionary<int, bool> labelsByFlowId,
            double w1, double w2, double w3,
            int k = 5)
        {
            if (flows == null || flows.Count == 0)
                return "{\"error\":\"Empty flows\",\"predictions\":[]}";

            try
            {
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);

                    dynamic simModule = Py.Import("similarity");

                    var jsonOptions = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = null,
                        ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles,
                    };
                    string flowsJson = JsonSerializer.Serialize(flows, jsonOptions);

                    // Преобразуем dict<int,bool> в dict<string,bool> для JSON
                    var labelsStr = labelsByFlowId
                        .ToDictionary(kv => kv.Key.ToString(), kv => kv.Value);
                    string labelsJson = JsonSerializer.Serialize(labelsStr);

                    _logger.LogInformation(
                        $"[kNN-Sim] Classifying {flows.Count} flows " +
                        $"(w1={w1}, w2={w2}, w3={w3}, k={k})");

                    dynamic resultPy = simModule.knn_classify_flows(
                        flowsJson, labelsJson, w1, w2, w3, k);
                    return resultPy?.ToString() ?? "{\"predictions\":[]}";
                }
            }
            catch (PythonException ex)
            {
                _logger.LogError(ex, "[kNN-Sim] Python error in KnnClassifyFlows");
                throw new Exception($"kNN classification failed: {ex.Message}");
            }
        }
    }
}
