using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace TrafficAnalysisAPI.Migrations
{
    /// <inheritdoc />
    public partial class InitialClean : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TrafficSessions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    SessionName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    StartTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    EndTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Description = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrafficSessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Username = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    PasswordHash = table.Column<string>(type: "text", nullable: false),
                    Role = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

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

            migrationBuilder.CreateTable(
                name: "NetworkPackets",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    SourceIP = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    DestinationIP = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    Protocol = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    PacketSize = table.Column<int>(type: "integer", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SessionId = table.Column<int>(type: "integer", nullable: true),
                    FlowId = table.Column<int>(type: "integer", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkPackets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_NetworkPackets_FlowMetrics_FlowId",
                        column: x => x.FlowId,
                        principalTable: "FlowMetrics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_NetworkPackets_TrafficSessions_SessionId",
                        column: x => x.SessionId,
                        principalTable: "TrafficSessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "CreatedAt", "PasswordHash", "Role", "Username" },
                values: new object[,]
                {
                    { 1, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "$2a$12$C83vSlJeLDe9HQKCTtAZauTtlT2s8sVbZtZIvGAmlrAR14wDDRkE.", "Admin", "admin" },
                    { 2, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "$2a$12$uMJ6PYfgWhWPNFTshq.o1uukT0yYAuju3J6mVv1M32MXtrFhpnYB2", "Analyst", "analyst" }
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

            migrationBuilder.CreateIndex(
                name: "IX_FlowMetrics_ThreatLevel",
                table: "FlowMetrics",
                column: "ThreatLevel");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkPackets_DestinationIP",
                table: "NetworkPackets",
                column: "DestinationIP");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkPackets_FlowId",
                table: "NetworkPackets",
                column: "FlowId");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkPackets_SessionId",
                table: "NetworkPackets",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkPackets_SourceIP",
                table: "NetworkPackets",
                column: "SourceIP");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkPackets_Timestamp",
                table: "NetworkPackets",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NetworkPackets");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "FlowMetrics");

            migrationBuilder.DropTable(
                name: "TrafficSessions");
        }
    }
}
