using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace TrafficAnalysisAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddFlowMetrics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FlowMetrics",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    SessionId = table.Column<int>(type: "integer", nullable: false),
                    SourceIP = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    DestinationIP = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    SourcePort = table.Column<int>(type: "integer", nullable: false),
                    DestinationPort = table.Column<int>(type: "integer", nullable: false),
                    Protocol = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    FlowStartTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FlowEndTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FlowDuration = table.Column<double>(type: "double precision", nullable: false),
                    TotalFwdPackets = table.Column<int>(type: "integer", nullable: false),
                    TotalBackwardPackets = table.Column<int>(type: "integer", nullable: false),
                    TotalLengthFwdPackets = table.Column<long>(type: "bigint", nullable: false),
                    TotalLengthBwdPackets = table.Column<long>(type: "bigint", nullable: false),
                    FwdPacketLengthMax = table.Column<double>(type: "double precision", nullable: false),
                    FwdPacketLengthMin = table.Column<double>(type: "double precision", nullable: false),
                    FwdPacketLengthMean = table.Column<double>(type: "double precision", nullable: false),
                    FwdPacketLengthStd = table.Column<double>(type: "double precision", nullable: false),
                    BwdPacketLengthMax = table.Column<double>(type: "double precision", nullable: false),
                    BwdPacketLengthMin = table.Column<double>(type: "double precision", nullable: false),
                    BwdPacketLengthMean = table.Column<double>(type: "double precision", nullable: false),
                    BwdPacketLengthStd = table.Column<double>(type: "double precision", nullable: false),
                    FlowBytesPerSec = table.Column<double>(type: "double precision", nullable: false),
                    FlowPacketsPerSec = table.Column<double>(type: "double precision", nullable: false),
                    FwdPacketsPerSec = table.Column<double>(type: "double precision", nullable: false),
                    BwdPacketsPerSec = table.Column<double>(type: "double precision", nullable: false),
                    FlowIATMean = table.Column<double>(type: "double precision", nullable: false),
                    FlowIATStd = table.Column<double>(type: "double precision", nullable: false),
                    FlowIATMax = table.Column<double>(type: "double precision", nullable: false),
                    FlowIATMin = table.Column<double>(type: "double precision", nullable: false),
                    FwdIATTotal = table.Column<double>(type: "double precision", nullable: false),
                    FwdIATMean = table.Column<double>(type: "double precision", nullable: false),
                    FwdIATStd = table.Column<double>(type: "double precision", nullable: false),
                    FwdIATMax = table.Column<double>(type: "double precision", nullable: false),
                    FwdIATMin = table.Column<double>(type: "double precision", nullable: false),
                    BwdIATTotal = table.Column<double>(type: "double precision", nullable: false),
                    BwdIATMean = table.Column<double>(type: "double precision", nullable: false),
                    BwdIATStd = table.Column<double>(type: "double precision", nullable: false),
                    BwdIATMax = table.Column<double>(type: "double precision", nullable: false),
                    BwdIATMin = table.Column<double>(type: "double precision", nullable: false),
                    FwdPSHFlags = table.Column<int>(type: "integer", nullable: false),
                    BwdPSHFlags = table.Column<int>(type: "integer", nullable: false),
                    FwdURGFlags = table.Column<int>(type: "integer", nullable: false),
                    BwdURGFlags = table.Column<int>(type: "integer", nullable: false),
                    FINFlagCount = table.Column<int>(type: "integer", nullable: false),
                    SYNFlagCount = table.Column<int>(type: "integer", nullable: false),
                    RSTFlagCount = table.Column<int>(type: "integer", nullable: false),
                    PSHFlagCount = table.Column<int>(type: "integer", nullable: false),
                    ACKFlagCount = table.Column<int>(type: "integer", nullable: false),
                    URGFlagCount = table.Column<int>(type: "integer", nullable: false),
                    CWEFlagCount = table.Column<int>(type: "integer", nullable: false),
                    ECEFlagCount = table.Column<int>(type: "integer", nullable: false),
                    FwdHeaderLength = table.Column<int>(type: "integer", nullable: false),
                    BwdHeaderLength = table.Column<int>(type: "integer", nullable: false),
                    MinSegSizeForward = table.Column<int>(type: "integer", nullable: false),
                    MinPacketLength = table.Column<double>(type: "double precision", nullable: false),
                    MaxPacketLength = table.Column<double>(type: "double precision", nullable: false),
                    PacketLengthMean = table.Column<double>(type: "double precision", nullable: false),
                    PacketLengthStd = table.Column<double>(type: "double precision", nullable: false),
                    PacketLengthVariance = table.Column<double>(type: "double precision", nullable: false),
                    AveragePacketSize = table.Column<double>(type: "double precision", nullable: false),
                    AvgFwdSegmentSize = table.Column<double>(type: "double precision", nullable: false),
                    AvgBwdSegmentSize = table.Column<double>(type: "double precision", nullable: false),
                    DownUpRatio = table.Column<double>(type: "double precision", nullable: false),
                    InitWinBytesForward = table.Column<int>(type: "integer", nullable: false),
                    InitWinBytesBackward = table.Column<int>(type: "integer", nullable: false),
                    ActDataPktFwd = table.Column<int>(type: "integer", nullable: false),
                    FwdAvgBytesBulk = table.Column<double>(type: "double precision", nullable: false),
                    FwdAvgPacketsBulk = table.Column<double>(type: "double precision", nullable: false),
                    FwdAvgBulkRate = table.Column<double>(type: "double precision", nullable: false),
                    BwdAvgBytesBulk = table.Column<double>(type: "double precision", nullable: false),
                    BwdAvgPacketsBulk = table.Column<double>(type: "double precision", nullable: false),
                    BwdAvgBulkRate = table.Column<double>(type: "double precision", nullable: false),
                    SubflowFwdPackets = table.Column<int>(type: "integer", nullable: false),
                    SubflowFwdBytes = table.Column<long>(type: "bigint", nullable: false),
                    SubflowBwdPackets = table.Column<int>(type: "integer", nullable: false),
                    SubflowBwdBytes = table.Column<long>(type: "bigint", nullable: false),
                    ActiveMean = table.Column<double>(type: "double precision", nullable: false),
                    ActiveStd = table.Column<double>(type: "double precision", nullable: false),
                    ActiveMax = table.Column<double>(type: "double precision", nullable: false),
                    ActiveMin = table.Column<double>(type: "double precision", nullable: false),
                    IdleMean = table.Column<double>(type: "double precision", nullable: false),
                    IdleStd = table.Column<double>(type: "double precision", nullable: false),
                    IdleMax = table.Column<double>(type: "double precision", nullable: false),
                    IdleMin = table.Column<double>(type: "double precision", nullable: false),
                    Label = table.Column<int>(type: "integer", nullable: true),
                    ThreatScore = table.Column<double>(type: "double precision", nullable: true),
                    ThreatLevel = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    PredictedBy = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FlowMetrics", x => x.Id);
                    table.ForeignKey(
                        name: "FK_FlowMetrics_TrafficSessions_SessionId",
                        column: x => x.SessionId,
                        principalTable: "TrafficSessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FlowMetrics_Protocol",
                table: "FlowMetrics",
                column: "Protocol");

            migrationBuilder.CreateIndex(
                name: "IX_FlowMetrics_SessionId",
                table: "FlowMetrics",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_FlowMetrics_SourceIP_DestinationIP",
                table: "FlowMetrics",
                columns: new[] { "SourceIP", "DestinationIP" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FlowMetrics");
        }
    }
}
