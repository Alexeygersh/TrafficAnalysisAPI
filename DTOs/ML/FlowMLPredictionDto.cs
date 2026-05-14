namespace TrafficAnalysisAPI.DTOs.ML
{
    // Результат ML-предсказания для одного flow (5-tuple).
    // Возвращается из POST /api/ml/flow-analyze.

    public class FlowMLPredictionDto
    {
        public int FlowId { get; set; }
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";

        // Классифицирован ли flow как атака (RF или IF или оба)
        public bool IsAttack { get; set; }

        // Уверенность Random Forest (0-1) — вероятность класса "атака"
        public double Confidence { get; set; }

        // Low / Medium / High / Critical
        public string ThreatLevel { get; set; } = "Low";

        // supervised / unsupervised / both / none
        public string Method { get; set; } = "none";

        // 0 = норма, 1 = атака (только RF)
        public int RfPrediction { get; set; }

        // true если Isolation Forest считает flow аномалией
        public bool IsAnomaly { get; set; }
    }

    // Сводный результат ML-анализа сессии на уровне flow
    public class FlowMLAnalyzeResultDto
    {
        public int SessionId { get; set; }
        public int TotalFlows { get; set; }
        public int AttackFlows { get; set; }
        public int AnomalyFlows { get; set; }
        public Dictionary<string, int> ThreatLevelBreakdown { get; set; } = new();
        public Dictionary<string, int> MethodBreakdown { get; set; } = new();
        public List<string> UsedFeatures { get; set; } = new();
        public long ElapsedMs { get; set; }
        public List<FlowMLPredictionDto> Predictions { get; set; } = new();
    }

    // Meta из global_features.json — то на чём обучалась модель
    public class ModelMetaDto
    {
        public List<string> FeatureNames { get; set; } = new();
        public string ModelVersion { get; set; } = "";
        public string ModelFile { get; set; } = "";
        public string TrainedOn { get; set; } = "";
        public Dictionary<string, List<string>>? FeaturesByBlock { get; set; }
        public string? SelectionMethod { get; set; }
    }
}
