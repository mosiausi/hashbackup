#!/usr/bin/env python3
"""
Backup Verification Tool
Checks if files from a source folder have been backed up to a destination
based on content (not filename) using SHA-256 hashing.
"""

import os
import sys
import hashlib
import argparse
import json
import csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import time

# Try to import paramiko for SSH support
try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("Warning: paramiko not installed. SSH functionality disabled.")
    print("Install with: pip3 install paramiko")


class BackupVerifier:
    def __init__(self, source, destination, compare_types=True, partial_hash=True, 
                 use_ssh=False, ssh_host=None, ssh_user=None, ssh_key=None, ssh_password=None, ssh_port=22):
        self.source = Path(source)
        self.destination = destination if use_ssh else Path(destination)
        self.compare_types = compare_types
        self.partial_hash = partial_hash
        self.use_ssh = use_ssh
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        self.ssh_client = None
        self.sftp = None
        self.use_sftp = True  # Try SFTP first, fallback to SSH commands
        
        self.results = {
            'backed_up': [],
            'missing': [],
            'total': 0,
            'start_time': datetime.now().isoformat(),
        }
        
    def log(self, message, level="INFO"):
        """Print log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print("[{0}] [{1}] {2}".format(timestamp, level, message))
        
    def connect_ssh(self):
        """Establish SSH connection"""
        if not SSH_AVAILABLE:
            raise Exception("paramiko not installed. Install with: pip3 install paramiko")
            
        self.log("Connecting to {0}@{1}:{2}...".format(self.ssh_user, self.ssh_host, self.ssh_port))
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            connect_kwargs = {
                'hostname': self.ssh_host,
                'port': self.ssh_port,
                'username': self.ssh_user,
                'timeout': 30,
                'banner_timeout': 60,
                'auth_timeout': 30
            }
            
            if self.ssh_key:
                key_path = os.path.expanduser(self.ssh_key)
                self.log("Using SSH key: {0}".format(key_path))
                connect_kwargs['key_filename'] = key_path
            elif self.ssh_password:
                self.log("Using password authentication")
                connect_kwargs['password'] = self.ssh_password
                connect_kwargs['look_for_keys'] = False
                connect_kwargs['allow_agent'] = False
            else:
                # Try default SSH keys
                self.log("Trying default SSH keys")
                connect_kwargs['look_for_keys'] = True
            
            self.ssh_client.connect(**connect_kwargs)
            self.log("SSH connection successful")
            
            self.log("Opening SFTP channel...")
            # Try to get SFTP with retries
            max_retries = 3
            sftp_failed = False
            for attempt in range(max_retries):
                try:
                    self.sftp = self.ssh_client.open_sftp()
                    self.log("SFTP channel established", "SUCCESS")
                    self.use_sftp = True
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        self.log("SFTP attempt {0} failed, retrying...".format(attempt + 1), "WARNING")
                        time.sleep(2)
                    else:
                        sftp_failed = True
                        self.log("SFTP not available, will use SSH commands instead", "WARNING")
                        self.use_sftp = False
            
            if not self.use_sftp:
                # Test if we can execute commands
                stdin, stdout, stderr = self.ssh_client.exec_command('echo "test"')
                if stdout.channel.recv_exit_status() != 0:
                    raise Exception("Cannot execute SSH commands on remote host")
            
        except paramiko.AuthenticationException as e:
            self.log("Authentication failed: {0}".format(e), "ERROR")
            self.log("Please verify your username and password", "ERROR")
            raise
        except paramiko.SSHException as e:
            self.log("SSH error: {0}".format(e), "ERROR")
            raise
        except Exception as e:
            self.log("SSH connection failed: {0}".format(e), "ERROR")
            raise
            
    def disconnect_ssh(self):
        """Close SSH connection"""
        if self.sftp:
            self.sftp.close()
        if self.ssh_client:
            self.ssh_client.close()
        self.log("SSH connection closed")
        
    def hash_file(self, filepath, is_remote=False):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        try:
            if is_remote:
                if self.use_sftp:
                    # Remote file via SFTP
                    with self.sftp.open(filepath, 'rb') as f:
                        if self.partial_hash:
                            chunk = f.read(1024 * 1024)
                            sha256_hash.update(chunk)
                        else:
                            chunk = f.read(8192)
                            while chunk:
                                sha256_hash.update(chunk)
                                chunk = f.read(8192)
                else:
                    # Remote file via SSH commands
                    if self.partial_hash:
                        cmd = 'head -c 1048576 "{0}" | base64'.format(filepath.replace('"', '\\"'))
                    else:
                        cmd = 'cat "{0}" | base64'.format(filepath.replace('"', '\\"'))
                    
                    stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                    exit_status = stdout.channel.recv_exit_status()
                    
                    if exit_status != 0:
                        error = stderr.read().decode('utf-8')
                        raise Exception("Failed to read file: {0}".format(error))
                    
                    import base64
                    file_data = base64.b64decode(stdout.read())
                    sha256_hash.update(file_data)
            else:
                # Local file
                with open(filepath, 'rb') as f:
                    if self.partial_hash:
                        chunk = f.read(1024 * 1024)
                        sha256_hash.update(chunk)
                    else:
                        chunk = f.read(8192)
                        while chunk:
                            sha256_hash.update(chunk)
                            chunk = f.read(8192)
                            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            self.log("Error hashing file {0}: {1}".format(filepath, e), "ERROR")
            return None
            
    def get_file_size(self, filepath, is_remote=False):
        """Get file size"""
        try:
            if is_remote:
                if self.use_sftp:
                    return self.sftp.stat(filepath).st_size
                else:
                    # Use SSH command
                    cmd = 'stat -c %s "{0}" 2>/dev/null || stat -f %z "{0}"'.format(filepath.replace('"', '\\"'))
                    stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                    result = stdout.read().decode('utf-8').strip()
                    return int(result) if result else 0
            else:
                return os.path.getsize(filepath)
        except:
            return 0
            
    def list_files_local(self, path):
        """List all files in local directory recursively"""
        files = []
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                if not filename.startswith('.'):  # Skip hidden files
                    filepath = os.path.join(root, filename)
                    files.append({
                        'path': filepath,
                        'name': filename,
                        'size': self.get_file_size(filepath),
                        'extension': os.path.splitext(filename)[1].lower().lstrip('.')
                    })
        return files
        
    def list_files_remote(self, path):
        """List all files in remote directory recursively via SFTP or SSH"""
        files = []
        
        if self.use_sftp:
            # Use SFTP
            def walk_remote(remote_path):
                try:
                    for entry in self.sftp.listdir_attr(remote_path):
                        remote_filepath = os.path.join(remote_path, entry.filename).replace('\\', '/')
                        
                        if entry.filename.startswith('.'):
                            continue
                        
                        try:
                            stat_info = self.sftp.stat(remote_filepath)
                            import stat as stat_module
                            if stat_module.S_ISDIR(stat_info.st_mode):
                                walk_remote(remote_filepath)
                            else:
                                files.append({
                                    'path': remote_filepath,
                                    'name': entry.filename,
                                    'size': entry.st_size,
                                    'extension': os.path.splitext(entry.filename)[1].lower().lstrip('.')
                                })
                        except:
                            continue
                            
                except Exception as e:
                    self.log("Error reading remote directory {0}: {1}".format(remote_path, e), "ERROR")
                    
            walk_remote(path)
        else:
            # Use SSH commands
            self.log("Using SSH commands to list files (slower than SFTP)...")
            cmd = 'find "{0}" -type f ! -name ".*" -exec stat -c "%n|%s" {{}} \\; 2>/dev/null || find "{0}" -type f ! -name ".*" -exec stat -f "%N|%z" {{}} \\;'.format(
                path.replace('"', '\\"')
            )
            
            stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=300)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode('utf-8')
                raise Exception("Failed to list files: {0}".format(error))
            
            for line in stdout:
                line = line.strip()
                if '|' in line:
                    filepath, size = line.rsplit('|', 1)
                    filename = os.path.basename(filepath)
                    files.append({
                        'path': filepath,
                        'name': filename,
                        'size': int(size),
                        'extension': os.path.splitext(filename)[1].lower().lstrip('.')
                    })
                    
        return files
        
    def group_by_extension(self, files):
        """Group files by extension"""
        grouped = defaultdict(list)
        for file_info in files:
            grouped[file_info['extension']].append(file_info)
        return grouped
        
    def verify_backup(self):
        """Main verification process"""
        start_time = time.time()
        
        # Connect to SSH if needed
        if self.use_ssh:
            self.connect_ssh()
            
        try:
            # List source files
            self.log("Scanning source folder...")
            source_files = self.list_files_local(self.source)
            self.log("Found {0} files in source".format(len(source_files)), "SUCCESS")
            
            if len(source_files) == 0:
                self.log("No files found in source folder", "WARNING")
                return
                
            # List destination files
            self.log("Scanning destination folder...")
            if self.use_ssh:
                dest_files = self.list_files_remote(self.destination)
            else:
                dest_files = self.list_files_local(self.destination)
            self.log("Found {0} files in destination".format(len(dest_files)), "SUCCESS")
            
            if len(dest_files) == 0:
                self.log("No files found in destination folder", "WARNING")
                # All source files are missing
                for file_info in source_files:
                    self.results['missing'].append({
                        'name': file_info['name'],
                        'size': file_info['size'],
                        'type': file_info['extension'],
                        'reason': 'Destination folder is empty'
                    })
                self.results['total'] = len(source_files)
                return
                
            # Group by extension if needed
            source_by_ext = self.group_by_extension(source_files)
            dest_by_ext = self.group_by_extension(dest_files)
            
            # Process each source file
            self.log("Starting file comparison...")
            processed = 0
            self.results['total'] = len(source_files)
            
            for source_file in source_files:
                processed += 1
                
                if processed % 10 == 0:
                    progress = (processed / float(len(source_files))) * 100
                    self.log("Progress: {0}/{1} ({2:.1f}%)".format(processed, len(source_files), progress))
                    
                source_ext = source_file['extension']
                
                # Determine which files to compare against
                if self.compare_types:
                    compare_against = dest_by_ext.get(source_ext, [])
                else:
                    compare_against = dest_files
                    
                if not compare_against:
                    self.results['missing'].append({
                        'name': source_file['name'],
                        'size': source_file['size'],
                        'type': source_ext,
                        'reason': 'No matching type in destination'
                    })
                    continue
                    
                # Filter by size (optimization)
                same_size_files = [f for f in compare_against if f['size'] == source_file['size']]
                
                if not same_size_files:
                    self.results['missing'].append({
                        'name': source_file['name'],
                        'size': source_file['size'],
                        'type': source_ext,
                        'reason': 'No matching size in destination'
                    })
                    continue
                    
                # Calculate hash for source file
                source_hash = self.hash_file(source_file['path'])
                
                if source_hash is None:
                    self.log("Skipping {0} - could not calculate hash".format(source_file['name']), "WARNING")
                    continue
                    
                # Check against destination files
                found = False
                for dest_file in same_size_files:
                    dest_hash = self.hash_file(dest_file['path'], is_remote=self.use_ssh)
                    
                    if dest_hash and source_hash == dest_hash:
                        self.results['backed_up'].append({
                            'source_name': source_file['name'],
                            'dest_name': dest_file['name'],
                            'size': source_file['size'],
                            'type': source_ext,
                            'hash': source_hash[:16]  # First 16 chars of hash
                        })
                        found = True
                        break
                        
                if not found:
                    self.results['missing'].append({
                        'name': source_file['name'],
                        'size': source_file['size'],
                        'type': source_ext,
                        'reason': 'Content not found in destination'
                    })
                    
            elapsed_time = time.time() - start_time
            self.results['end_time'] = datetime.now().isoformat()
            self.results['duration_seconds'] = elapsed_time
            
            self.log("Verification complete in {0:.2f} seconds".format(elapsed_time), "SUCCESS")
            self.print_summary()
            
        finally:
            if self.use_ssh:
                self.disconnect_ssh()
                
    def print_summary(self):
        """Print summary of results"""
        print("\n" + "="*60)
        print("BACKUP VERIFICATION SUMMARY")
        print("="*60)
        print("Total files in source: {0}".format(self.results['total']))
        print("Files backed up: {0}".format(len(self.results['backed_up'])))
        print("Files missing: {0}".format(len(self.results['missing'])))
        
        if self.results['total'] > 0:
            percentage = (len(self.results['backed_up']) / float(self.results['total'])) * 100
            print("Backup coverage: {0:.1f}%".format(percentage))
        print("="*60 + "\n")
        
    def export_csv(self, filename):
        """Export results to CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Status', 'Source File', 'Destination File', 'Size', 'Type', 'Hash/Reason'])
            
            for item in self.results['backed_up']:
                writer.writerow([
                    'Backed Up',
                    item['source_name'],
                    item['dest_name'],
                    item['size'],
                    item['type'],
                    item['hash']
                ])
                
            for item in self.results['missing']:
                writer.writerow([
                    'Missing',
                    item['name'],
                    '',
                    item['size'],
                    item['type'],
                    item['reason']
                ])
                
        self.log("Results exported to {0}".format(filename), "SUCCESS")
        
    def export_json(self, filename):
        """Export results to JSON"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        self.log("Results exported to {0}".format(filename), "SUCCESS")
        
    def export_html(self, filename):
        """Export results to HTML"""
        coverage = (len(self.results['backed_up']) / float(self.results['total']) * 100) if self.results['total'] > 0 else 0
        
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Backup Verification Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .summary h2 {{ margin-top: 0; }}
        .stat {{ display: inline-block; margin: 10px 20px; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; opacity: 0.9; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #4CAF50; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .backed-up {{ background: #d4edda !important; }}
        .missing {{ background: #f8d7da !important; }}
        .section {{ margin: 30px 0; }}
        .timestamp {{ color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Backup Verification Report</h1>
        <p class="timestamp">Generated: {0}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="stat">
                <div class="stat-value">{1}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat">
                <div class="stat-value">{2}</div>
                <div class="stat-label">Backed Up</div>
            </div>
            <div class="stat">
                <div class="stat-value">{3}</div>
                <div class="stat-label">Missing</div>
            </div>
            <div class="stat">
                <div class="stat-value">{4:.1f}%</div>
                <div class="stat-label">Coverage</div>
            </div>
        </div>
        
        <div class="section">
            <h2>✅ Backed Up Files ({5})</h2>
            <table>
                <tr>
                    <th>Source File</th>
                    <th>Destination File</th>
                    <th>Size (bytes)</th>
                    <th>Type</th>
                    <th>Hash</th>
                </tr>
""".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            self.results['total'],
            len(self.results['backed_up']),
            len(self.results['missing']),
            coverage,
            len(self.results['backed_up'])
        )
        
        for item in self.results['backed_up']:
            html += """
                <tr class="backed-up">
                    <td>{0}</td>
                    <td>{1}</td>
                    <td>{2:,}</td>
                    <td>.{3}</td>
                    <td><code>{4}</code></td>
                </tr>
""".format(item['source_name'], item['dest_name'], item['size'], item['type'], item['hash'])
        
        html += """
            </table>
        </div>
        
        <div class="section">
            <h2>❌ Missing Files ({0})</h2>
            <table>
                <tr>
                    <th>File Name</th>
                    <th>Size (bytes)</th>
                    <th>Type</th>
                    <th>Reason</th>
                </tr>
""".format(len(self.results['missing']))
        
        for item in self.results['missing']:
            html += """
                <tr class="missing">
                    <td>{0}</td>
                    <td>{1:,}</td>
                    <td>.{2}</td>
                    <td>{3}</td>
                </tr>
""".format(item['name'], item['size'], item['type'], item['reason'])
        
        html += """
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        self.log("Results exported to {0}".format(filename), "SUCCESS")


def main():
    parser = argparse.ArgumentParser(
        description='Verify if files have been backed up based on content',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare two local folders
  python backup_checker.py /path/to/source /path/to/destination
  
  # Compare with remote NAS via SSH
  python backup_checker.py /path/to/source /remote/path --ssh --host 192.168.1.104 --user admin
  
  # Compare all file types and export results
  python backup_checker.py /path/to/source /path/to/dest --no-compare-types --export-csv report.csv
  
  # Use SSH with key authentication
  python backup_checker.py /path/to/source /remote/path --ssh --host 192.168.1.104 --user admin --key ~/.ssh/id_rsa
        """
    )
    
    parser.add_argument('source', help='Source folder path')
    parser.add_argument('destination', help='Destination folder path (or remote path if using SSH)')
    parser.add_argument('--no-compare-types', action='store_true', help='Compare across all file types')
    parser.add_argument('--full-hash', action='store_true', help='Use full file hashing (slower but more accurate)')
    parser.add_argument('--ssh', action='store_true', help='Use SSH for remote destination')
    parser.add_argument('--host', help='SSH host (e.g., 192.168.1.104)')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--user', help='SSH username')
    parser.add_argument('--key', help='Path to SSH private key')
    parser.add_argument('--password', help='SSH password (not recommended, use key instead)')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--export-html', help='Export results to HTML file')
    
    args = parser.parse_args()
    
    # Validate SSH arguments
    if args.ssh and not (args.host and args.user):
        print("Error: --ssh requires --host and --user")
        sys.exit(1)
        
    if args.ssh and not SSH_AVAILABLE:
        print("Error: paramiko library required for SSH")
        print("Install with: pip3 install paramiko")
        sys.exit(1)
        
    # Create verifier
    verifier = BackupVerifier(
        source=args.source,
        destination=args.destination,
        compare_types=not args.no_compare_types,
        partial_hash=not args.full_hash,
        use_ssh=args.ssh,
        ssh_host=args.host,
        ssh_user=args.user,
        ssh_key=args.key,
        ssh_password=args.password,
        ssh_port=args.port
    )
    
    # Run verification
    try:
        verifier.verify_backup()
        
        # Export results
        if args.export_csv:
            verifier.export_csv(args.export_csv)
        if args.export_json:
            verifier.export_json(args.export_json)
        if args.export_html:
            verifier.export_html(args.export_html)
            
    except KeyboardInterrupt:
        print("\n\nVerification cancelled by user")
        sys.exit(1)
    except Exception as e:
        print("\nError: {0}".format(e))
        sys.exit(1)


if __name__ == '__main__':
    main()