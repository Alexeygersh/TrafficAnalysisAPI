using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814

namespace TrafficAnalysisAPI.Migrations
{
    public partial class InitialCreate : Migration
    {
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
                    SessionId = table.Column<int>(type: "integer", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkPackets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_NetworkPackets_TrafficSessions_SessionId",
                        column: x => x.SessionId,
                        principalTable: "TrafficSessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "TrafficAnalyses",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    PacketId = table.Column<int>(type: "integer", nullable: false),
                    ThreatLevel = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    IsMalicious = table.Column<bool>(type: "boolean", nullable: false),
                    MLModelScore = table.Column<double>(type: "double precision", nullable: false),
                    DetectedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrafficAnalyses", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrafficAnalyses_NetworkPackets_PacketId",
                        column: x => x.PacketId,
                        principalTable: "NetworkPackets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "CreatedAt", "PasswordHash", "Role", "Username" },
                values: new object[,]
                {
                    { 1, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "$2a$11$Zx8H1qGKp5L2rN8dK7vZx.YQ3L5mB9Kp2fH7nJ4xR6tW8yV3cA1Bm", "Admin", "admin" },
                    { 2, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "$2a$11$xB5yL8Np2K6fR9tM3vJ7c.WQ2L4mA8Jp1eG6mI3wP5rU7xT2bZ0Am", "Analyst", "analyst" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkPackets_DestinationIP",
                table: "NetworkPackets",
                column: "DestinationIP");

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
                name: "IX_TrafficAnalyses_PacketId",
                table: "TrafficAnalyses",
                column: "PacketId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TrafficAnalyses_ThreatLevel",
                table: "TrafficAnalyses",
                column: "ThreatLevel");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TrafficAnalyses");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "NetworkPackets");

            migrationBuilder.DropTable(
                name: "TrafficSessions");
        }
    }
}
