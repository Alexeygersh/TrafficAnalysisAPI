using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<NetworkPacket> NetworkPackets { get; set; }
        public DbSet<TrafficAnalysis> TrafficAnalyses { get; set; }
        public DbSet<TrafficSession> TrafficSessions { get; set; }
        public DbSet<SourceMetrics> SourceMetrics { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Настройка связей
            modelBuilder.Entity<NetworkPacket>()
                .HasOne(p => p.Session)
                .WithMany(s => s.Packets)
                .HasForeignKey(p => p.SessionId)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<TrafficAnalysis>()
                .HasOne(a => a.Packet)
                .WithOne(p => p.Analysis)
                .HasForeignKey<TrafficAnalysis>(a => a.PacketId)
                .OnDelete(DeleteBehavior.Cascade);

            // Индексы
            modelBuilder.Entity<NetworkPacket>()
                .HasIndex(p => p.SourceIP);

            modelBuilder.Entity<NetworkPacket>()
                .HasIndex(p => p.DestinationIP);

            modelBuilder.Entity<NetworkPacket>()
                .HasIndex(p => p.Timestamp);

            modelBuilder.Entity<TrafficAnalysis>()
                .HasIndex(a => a.ThreatLevel);

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();


            modelBuilder.Entity<User>().HasData(
            new User
            {
                    Id = 1,
                    Username = "admin",
                    PasswordHash = "$2a$12$C83vSlJeLDe9HQKCTtAZauTtlT2s8sVbZtZIvGAmlrAR14wDDRkE.", // BCrypt.Net.BCrypt.HashPassword("Admin123!")
                    Role = "Admin",
                    CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new User
            {
                    Id = 2,
                    Username = "analyst",
                    PasswordHash = "$2a$12$uMJ6PYfgWhWPNFTshq.o1uukT0yYAuju3J6mVv1M32MXtrFhpnYB2", // Analyst123!
                    Role = "Analyst",
                    CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                }
            );


            // Тестовые данные для сессии
            modelBuilder.Entity<TrafficSession>().HasData(
                new TrafficSession
                {
                    Id = 1,
                    SessionName = "Test Session 2025-01-12",
                    StartTime = new DateTime(2025, 10, 19, 12, 0, 0, DateTimeKind.Utc),
                    Description = "Тестовая сессия для демонстрации"
                }
            );

            // Тестовые данные для пакетов
            modelBuilder.Entity<NetworkPacket>().HasData(
                new NetworkPacket
                {
                    Id = 1,
                    SourceIP = "192.168.1.1",
                    DestinationIP = "10.0.0.1",
                    Port = 80,
                    Protocol = "TCP",
                    PacketSize = 500,
                    Timestamp = new DateTime(2025, 10, 19, 12, 5, 0, DateTimeKind.Utc),
                    SessionId = 1
                },
                new NetworkPacket
                {
                    Id = 2,
                    SourceIP = "45.142.120.15",
                    DestinationIP = "10.0.0.2",
                    Port = 23,
                    Protocol = "TCP",
                    PacketSize = 2000,
                    Timestamp = new DateTime(2025, 10, 19, 12, 10, 0, DateTimeKind.Utc),
                    SessionId = 1
                },
                new NetworkPacket
                {
                    Id = 3,
                    SourceIP = "45.142.120.15",
                    DestinationIP = "10.0.0.3",
                    Port = 445,
                    Protocol = "TCP",
                    PacketSize = 1800,
                    Timestamp = new DateTime(2025, 10, 19, 12, 15, 0, DateTimeKind.Utc),
                    SessionId = 1
                },
                new NetworkPacket
                {
                    Id = 4,
                    SourceIP = "192.168.1.2",
                    DestinationIP = "10.0.0.4",
                    Port = 3389,
                    Protocol = "TCP",
                    PacketSize = 1600,
                    Timestamp = new DateTime(2025, 10, 19, 12, 20, 0, DateTimeKind.Utc),
                    SessionId = 1
                },
                new NetworkPacket
                {
                    Id = 5,
                    SourceIP = "45.142.120.15",
                    DestinationIP = "10.0.0.5",
                    Port = 443,
                    Protocol = "HTTPS",
                    PacketSize = 600,
                    Timestamp = new DateTime(2025, 10, 19, 12, 25, 0, DateTimeKind.Utc),
                    SessionId = 1
                }
            );

            // Тестовые данные для анализа трафика
            modelBuilder.Entity<TrafficAnalysis>().HasData(
                new TrafficAnalysis
                {
                    Id = 1,
                    PacketId = 2,
                    ThreatLevel = "High",
                    IsMalicious = true,
                    MLModelScore = 0.7,
                    DetectedAt = new DateTime(2025, 10, 19, 12, 10, 0, DateTimeKind.Utc)
                },
                new TrafficAnalysis
                {
                    Id = 2,
                    PacketId = 3,
                    ThreatLevel = "Critical",
                    IsMalicious = true,
                    MLModelScore = 0.85,
                    DetectedAt = new DateTime(2025, 10, 19, 12, 15, 0, DateTimeKind.Utc)
                },
                new TrafficAnalysis
                {
                    Id = 3,
                    PacketId = 4,
                    ThreatLevel = "Medium",
                    IsMalicious = false,
                    MLModelScore = 0.5,
                    DetectedAt = new DateTime(2025, 10, 19, 12, 20, 0, DateTimeKind.Utc)
                },
                new TrafficAnalysis
                {
                    Id = 4,
                    PacketId = 5,
                    ThreatLevel = "Low",
                    IsMalicious = false,
                    MLModelScore = 0.3,
                    DetectedAt = new DateTime(2025, 10, 19, 12, 25, 0, DateTimeKind.Utc)
                }
            );

            // Индексы для SourceMetrics
            modelBuilder.Entity<SourceMetrics>()
                .HasIndex(m => m.SourceIP);

            modelBuilder.Entity<SourceMetrics>()
                .HasIndex(m => m.ClusterId);

            modelBuilder.Entity<SourceMetrics>()
                .HasIndex(m => m.IsDangerous);


        }
    }
}