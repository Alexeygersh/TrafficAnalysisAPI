import csv
import json
import io
import re
from typing import List, Dict, Any


def parse_wireshark_csv(csv_content: str) -> str:
    packets = []
    
    try:
        csv_file = io.StringIO(csv_content)
        reader = csv.DictReader(csv_file)
        
        for row_num, row in enumerate(reader, 1):
            try:
                packet = parse_packet_row(row)
                if packet:
                    packets.append(packet)
            except Exception as e:
                print(f"Row {row_num}: {e}")
                continue
    except Exception as e:
        print(f"CSV parse error: {e}")
    
    return json.dumps(packets, ensure_ascii=False)

def parse_packet_row(row: Dict[str, Any]) -> Dict[str, Any]:
    port = extract_port(row.get('Info', ''))
    
    return {
        'no': int(row.get('No.', 0) or 0),
        'time': float(row.get('Time', 0) or 0),
        'sourceIP': row.get('Source', '') or '',
        'destinationIP': row.get('Destination', '') or '',
        'protocol': row.get('Protocol', '') or '',
        'length': int(row.get('Length', 0) or 0),
        'port': port,
        'info': row.get('Info', '') or ''
    }

def extract_port(info_string):
    #- "60662 > 443 [ACK]" -> 443 (destination port)
    #- "443 > 60662 [ACK]" -> 60662 (destination port)

    match = re.search(r'(\d+)\s*>\s*(\d+)', info_string)
    if match:
        return int(match.group(2))
    
    match = re.search(r':(\d+)', info_string)
    if match:
        return int(match.group(1))
    
    return 0

"""


def parse_wireshark_csv(csv_content):
    packets = []
    lines = csv_content.strip().split('\n')
    
    # CSV reader
    reader = csv.DictReader(lines)
    
    for row in reader:
        try:
            packet = parse_packet_row(row)
            if packet:
                packets.append(packet)
        except Exception as e:
            print(f"Error parsing row: {e}")
            continue
    
    return json.dumps(packets)


def parse_packet_row(row):
    port = extract_port(row.get('Info', ''))
    
    packet = {
        'no': int(row.get('No.', 0)),
        'time': float(row.get('Time', 0)),
        'sourceIP': row.get('Source', '').strip(),
        'destinationIP': row.get('Destination', '').strip(),
        'protocol': row.get('Protocol', '').strip(),
        'length': int(row.get('Length', 0)),
        'port': port,
        'info': row.get('Info', '').strip()
    }
    
    return packet


def calculate_session_metrics(json_data):
    packets = json.loads(json_data)
    
    if not packets:
        return json.dumps([])
    
    sources = {}
    
    for packet in packets:
        ip = packet['sourceIP']
        
        if ip not in sources:
            sources[ip] = {
                'sourceIP': ip,
                'packetCount': 0,
                'totalLength': 0,
                'firstTime': packet['time'],
                'lastTime': packet['time'],
                'protocols': set(),
                'ports': []
            }
        
        sources[ip]['packetCount'] += 1
        sources[ip]['totalLength'] += packet['length']
        sources[ip]['lastTime'] = max(sources[ip]['lastTime'], packet['time'])
        sources[ip]['protocols'].add(packet['protocol'])
        sources[ip]['ports'].append(packet['port'])
    
    result = []
    for ip, data in sources.items():
        duration = data['lastTime'] - data['firstTime']
        
        if duration == 0:
            duration = 0.001
        
        result.append({
            'sourceIP': ip,
            'packetCount': data['packetCount'],
            'packetsPerSecond': data['packetCount'] / duration,
            'averagePacketSize': data['totalLength'] / data['packetCount'],
            'totalBytes': data['totalLength'],
            'duration': duration,
            'protocols': list(data['protocols']),
            'uniquePorts': len(set(data['ports']))
        })
    
    return json.dumps(result)

"""