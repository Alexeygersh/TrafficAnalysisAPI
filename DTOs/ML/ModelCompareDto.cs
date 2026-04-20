namespace TrafficAnalysisAPI.DTOs.ML
{
    /// <summary>
    /// Результат сравнения двух моделей на одной сессии.
    /// Возвращается из POST /api/ml/compare?sessionId=X
    /// </summary>
    public class ModelCompareResultDto
    {
        public int SessionId { get; set; }
        public int TotalFlows { get; set; }

        /// <summary>Сводка по модели Random Forest</summary>
        public ModelSummaryDto RfModel { get; set; } = new();

        /// <summary>Сводка по модели CatBoost</summary>
        public ModelSummaryDto CatBoostModel { get; set; } = new();

        /// <summary>Согласованность моделей (сколько совпадают)</summary>
        public AgreementStatsDto Agreement { get; set; } = new();

        /// <summary>Попарное сравнение предсказаний на каждом flow</summary>
        public List<FlowComparisonRowDto> Comparison { get; set; } = new();
    }

    /// <summary>Краткая сводка по одной модели в рамках сравнения.</summary>
    public class ModelSummaryDto
    {
        /// <summary>Сколько flows эта модель отметила как атаки</summary>
        public int AttackFlows { get; set; }

        /// <summary>Время инференса в мс</summary>
        public long ElapsedMs { get; set; }

        /// <summary>Список признаков на которых модель обучалась</summary>
        public List<string> Features { get; set; } = new();

        /// <summary>Метрики качества (accuracy/f1/roc_auc) из обучения</summary>
        public Dictionary<string, object>? Metrics { get; set; }
    }

    /// <summary>Статистика согласованности двух моделей.</summary>
    public class AgreementStatsDto
    {
        /// <summary>Обе модели сказали "атака"</summary>
        public int BothAttack { get; set; }

        /// <summary>Обе модели сказали "норма"</summary>
        public int BothNormal { get; set; }

        /// <summary>Модели разошлись</summary>
        public int Disagree { get; set; }

        /// <summary>Доля согласия: (BothAttack + BothNormal) / Total</summary>
        public double AgreementRate { get; set; }
    }

    /// <summary>Попарное сравнение предсказаний на одном flow.</summary>
    public class FlowComparisonRowDto
    {
        public int FlowId { get; set; }
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";

        // RF
        public bool RfIsAttack { get; set; }
        public double RfConfidence { get; set; }
        public string RfThreatLevel { get; set; } = "Low";
        public string RfMethod { get; set; } = "none";

        // CatBoost
        public bool CatBoostIsAttack { get; set; }
        public double CatBoostConfidence { get; set; }
        public string CatBoostThreatLevel { get; set; } = "Low";
        public string CatBoostMethod { get; set; } = "none";

        /// <summary>Согласны ли модели (обе атака или обе норма)</summary>
        public bool Agree { get; set; }
    }
}
