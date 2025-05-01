import psutil
import pandas as pd
import numpy as np
from datetime import datetime
import socket
import time

def extract_system_logs():
    """Extract relevant system metrics and network connections."""
    logs = []
    
    try:
        # Get network connections
        connections = psutil.net_connections()
        
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                # Basic connection info
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'count': len(connections),
                    'logged_in': 1 if psutil.users() else 0,
                    
                    # Calculate error rates (example metrics)
                    'srv_serror_rate': 0.0,  # You'll need to track these over time
                    'serror_rate': 0.0,
                    'dst_host_serror_rate': 0.0,
                    'dst_host_same_srv_rate': 0.0,
                    'dst_host_srv_serror_rate': 0.0,
                    'dst_host_srv_count': 0,
                    'same_srv_rate': 0.0,
                    
                    # Protocol type
                    'protocol_type': conn.type if hasattr(conn, 'type') else 'tcp',
                    
                    # Service (port mapping)
                    'service': get_service_name(conn.laddr.port if hasattr(conn.laddr, 'port') else 0),
                    
                    # Connection status flags
                    'status': conn.status
                }
                logs.append(log_entry)
                
    except Exception as e:
        print(f"Error extracting logs: {e}")
        
    return logs

def get_service_name(port):
    """Map port numbers to service names."""
    common_ports = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'domain',
        80: 'http',
        443: 'http_443',
        3306: 'mysql'
    }
    return common_ports.get(port, 'other')

def preprocess_logs(logs):
    """Preprocess logs to match the training data format."""
    df = pd.DataFrame(logs)
    
    # Convert protocol_type to one-hot encoding
    protocol_dummies = pd.get_dummies(df['protocol_type'], prefix='protocol_type')
    
    # Convert service to one-hot encoding
    service_dummies = pd.get_dummies(df['service'], prefix='service')
    
    # Initialize all expected columns from training data
    expected_columns = ['count', 'logged_in', 'srv_serror_rate', 'serror_rate',
                       'dst_host_serror_rate', 'dst_host_same_srv_rate',
                       'dst_host_srv_serror_rate', 'dst_host_srv_count',
                       'same_srv_rate']
    
    # Add protocol and service columns
    all_protocols = ['icmp', 'tcp', 'udp']
    all_services = ['IRC', 'X11', 'Z39_50', 'aol', 'auth', 'bgp', 'courier',
                   'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u',
                   'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp',
                   'ftp_data', 'gopher', 'harvest', 'hostnames', 'http',
                   'http_2784', 'http_443', 'http_8001', 'imap4', 'iso_tsap',
                   'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name',
                   'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat',
                   'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2',
                   'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje',
                   'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup',
                   'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i',
                   'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois']
    
    # Create empty columns for all expected features
    for protocol in all_protocols:
        if f'protocol_type_{protocol}' not in protocol_dummies.columns:
            protocol_dummies[f'protocol_type_{protocol}'] = 0
            
    for service in all_services:
        if f'service_{service}' not in service_dummies.columns:
            service_dummies[f'service_{service}'] = 0
    
    # Normalize numerical columns
    for col in expected_columns:
        if col in df.columns:
            df[col] = (df[col] - df[col].mean()) / df[col].std()
    
    # Combine all features
    preprocessed_df = pd.concat([df[expected_columns], protocol_dummies, service_dummies], axis=1)
    
    return preprocessed_df

if __name__ == "__main__":
    while True:
        logs = extract_system_logs()
        if logs:
            preprocessed_data = preprocess_logs(logs)
            # Save to CSV or send to your application
            preprocessed_data.to_csv('system_logs.csv', index=False)
        time.sleep(30)  # Extract logs every minute