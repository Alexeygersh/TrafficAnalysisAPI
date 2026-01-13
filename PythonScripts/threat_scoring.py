import json
import numpy as np

SUSPICIOUS_PORTS = [23, 135, 139, 445, 3389, 5900, 21, 22]
HIGH_RISK_PORTS = [23, 3389, 5900]  # Telnet, RDP, VNC

DANGEROUS_PROTOCOLS = ['TELNET', 'FTP', 'TFTP']

def calculate_packet_threat_score(json_data):
    """
    Calc threat score for packet
    
    Args:
        json_data: JSON
    
    Returns:
        float: threat score 0-1
    """
    data = json.loads(json_data)
    
    score = 0.0
    reasons = []
    
    # 1. Analyze port (30%)
    port_score, port_reasons = analyze_port(data.get('port', 0))
    score += port_score * 0.3
    reasons.extend(port_reasons)
    
    # 2. Packet size (20%)
    size_score, size_reasons = analyze_packet_size(data.get('packetSize', 0))
    score += size_score * 0.2
    reasons.extend(size_reasons)
    
    # 3. Protocol (15%)
    protocol_score, protocol_reasons = analyze_protocol(data.get('protocol', ''))
    score += protocol_score * 0.15
    reasons.extend(protocol_reasons)
    
    # 4. Metrics source (25%)
    source_score, source_reasons = analyze_source_behavior(data)
    score += source_score * 0.25
    reasons.extend(source_reasons)
    
    # 5. cluster (10%)
    cluster_score, cluster_reasons = analyze_cluster(data)
    score += cluster_score * 0.1
    reasons.extend(cluster_reasons)
    
    return json.dumps({
        'threatScore': min(score, 1.0),
        'threatLevel': get_threat_level(score),
        'isMalicious': score >= 0.6,
        'reasons': reasons
    })


def analyze_port(port):
    if port in HIGH_RISK_PORTS:
        return 1.0, [f"High risk port: {port}"]
    elif port in SUSPICIOUS_PORTS:
        return 0.7, [f"Suspicious port: {port}"]
    elif port < 1024:
        return 0.3, [f"System port: {port}"]
    else:
        return 0.0, []


def analyze_packet_size(size):
    if size > 8000:
        return 1.0, [f"Very large packet: {size} bytes"]
    elif size > 1500:
        return 0.6, [f"Large packet: {size} bytes"]
    elif size < 60:
        return 0.3, [f"Tiny packet: {size} bytes (possible scan)"]
    else:
        return 0.0, []


def analyze_protocol(protocol):
    protocol_upper = protocol.upper()
    
    if protocol_upper in DANGEROUS_PROTOCOLS:
        return 1.0, [f"Dangerous protocol: {protocol}"]
    elif protocol_upper == 'ICMP':
        return 0.5, ["ICMP traffic (possible reconnaissance)"]
    else:
        return 0.0, []


def analyze_source_behavior(data):
    score = 0.0
    reasons = []
    
    # High speed
    pps = data.get('packetsPerSecond', 0)
    if pps > 1000:
        score += 1.0
        reasons.append(f"Very high packet rate: {pps:.1f} pkt/s")
    elif pps > 500:
        score += 0.7
        reasons.append(f"High packet rate: {pps:.1f} pkt/s")
    elif pps > 100:
        score += 0.3
        reasons.append(f"Elevated packet rate: {pps:.1f} pkt/s")
    
    # Unique ports (port scanning)
    unique_ports = data.get('uniquePorts', 0)
    if unique_ports > 50:
        score += 0.8
        reasons.append(f"Port scanning detected: {unique_ports} unique ports")
    elif unique_ports > 20:
        score += 0.4
        reasons.append(f"Multiple ports accessed: {unique_ports}")
    
    return min(score, 1.0), reasons


def analyze_cluster(data):
    if data.get('isDangerous', False):
        danger_score = data.get('dangerScore', 0)
        return danger_score, [f"Belongs to dangerous cluster (score: {danger_score:.2f})"]
    return 0.0, []


def get_threat_level(score):
    if score >= 0.8:
        return "Critical"
    elif score >= 0.6:
        return "High"
    elif score >= 0.4:
        return "Medium"
    else:
        return "Low"


def batch_score_packets(json_data):
    """
    Calc threat score for packet list
    
    Args:
        json_data: JSON
    
    Returns:
        JSON threat scores
    """
    packets = json.loads(json_data)
    results = []
    
    for packet in packets:
        packet_json = json.dumps(packet)
        score_result = json.loads(calculate_packet_threat_score(packet_json))
        
        results.append({
            'packetId': packet.get('id'),
            **score_result
        })
    
    return json.dumps(results)
