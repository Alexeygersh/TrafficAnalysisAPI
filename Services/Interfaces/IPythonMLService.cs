using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.DTOs.ML;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    /// <summary>
    /// Сервис для Python-интеграции. Работает только на flow-уровне:
    ///   - построение flow-признаков из сырых пакетов (flow_features.py)
    ///   - ML-предсказания для списка flow (hybrid_ids.py / catboost_ids.py)
    /// </summary>
    public interface IPythonMLService
    {
        /// <summary>
        /// Строит flow-признаки из списка сырых пакетов (извлечённых из .pcap).
        /// Вызывает Python-модуль flow_features.py.
        /// </summary>
        List<FlowFeaturesDto> BuildFlowsFromPackets(
            List<TrafficAnalysisAPI.Services.Implementations.RawPacket> packets);


        /// ML-предсказание для списка flow.
        /// modelType:
        ///   "rf"       — RandomForest + Isolation Forest, hybrid_ids_v2.pkl
        ///   "catboost" — CatBoost + Isolation Forest, catboost_ids_v2.pkl
        List<FlowMLPredictionDto> PredictFlowsBatch(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            string modelType = "rf");


        /// Режим 1: Поиск k flows наиболее похожих на target по формуле:
        ///   Sim = w1·Sim_port + w2·Sim_num + w3·Sim_bin
        /// Возвращает JSON-строку с targetFlow, weights, blocks, results.
        string FindSimilarFlows(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            int targetFlowId,
            double w1, double w2, double w3,
            int k = 10);


        /// Режим 2: kNN-классификация всех flows на основе меры сходства.
        /// Использует labels (метки от ML-модели) как обучающую выборку.
        /// Для каждого flow находит k ближайших соседей (leave-one-out)
        /// и определяет класс голосованием.
        /// labelsByFlowId: словарь {flowId -> isAttack}.
        string KnnClassifyFlows(
            List<TrafficAnalysisAPI.Models.FlowMetrics> flows,
            Dictionary<int, bool> labelsByFlowId,
            double w1, double w2, double w3,
            int k = 5);
    }
}
