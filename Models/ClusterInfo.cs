namespace TrafficAnalysisAPI.Models
{
    public class ClusterInfo
    {
        public int ClusterId { get; set; }
        public string ClusterName { get; set; }
        public bool IsDangerous { get; set; }
        public double DangerScore { get; set; }
        public int SourceCount { get; set; }
        public double AverageSpeed { get; set; }
        public double MaxSpeed { get; set; }
    }
}