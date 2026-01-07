#!/usr/bin/env python3  
#using PATH environment variable (more portable) enable running ./subdomain_enum.py directly rather than having to run python3 ./subdomain_enum.py

import argparse
import subprocess
import sys
import os
import time
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv() #environment variables for sensitive info such as bot tokens for telegram notification


# colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def print_status(message, status_type="info"):
    #printing formatted status messages with colors
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status_type == "success":
        print(f"{Colors.GREEN}[{timestamp}] [+] {message}{Colors.ENDC}")
    elif status_type == "error":
        print(f"{Colors.FAIL}[{timestamp}] [-] {message}{Colors.ENDC}")
    elif status_type == "warning":
        print(f"{Colors.WARNING}[{timestamp}] [!] {message}{Colors.ENDC}")
    elif status_type == "info":
        print(f"{Colors.BLUE}[{timestamp}] [*] {message}{Colors.ENDC}")
    else:
        print(f"[{timestamp}] [*] {message}")

def check_tool_installed(tool_name):
    #checking if required tool is installed and accessible
    try:
        result = subprocess.run(['which', tool_name], 
                               capture_output=True, 
                               text=True)
        if result.returncode == 0:
            return True
        else:
            # checking with command -v
            result = subprocess.run(['command', '-v', tool_name],
                                   capture_output=True,
                                   text=True)
            return result.returncode == 0
    except Exception as e:
        return False
    


def run_subfinder(domain, output_file):

    print_status(f"Starting subdomain enumeration for: {domain}")
    
    # building subfinder command
    cmd = ['subfinder', '-d', domain, '-silent']
    
    try:
        print_status(f"Running command: {' '.join(cmd)}")
        
        # executing subfinder
        result = subprocess.run(cmd, 
                               capture_output=True, 
                               text=True, 
                               timeout=300)  
        
        if result.returncode != 0:
            print_status(f"Subfinder failed: {result.stderr}", "error")
            return []
        
        # extracting subdomains from output
        subdomains = result.stdout.strip().split('\n')

        # filtering out empty lines
        subdomains = [sub for sub in subdomains if sub.strip()]
        
        # removing duplicates while preserving order
        unique_subdomains = []
        seen = set()
        for sub in subdomains:
            if sub not in seen:
                seen.add(sub)
                unique_subdomains.append(sub)
        
        print_status(f"Found {len(unique_subdomains)} unique subdomains", "success")
        
        # saving to file
        with open(output_file, 'w') as f:
            for subdomain in unique_subdomains:
                f.write(f"{subdomain}\n")
        
        print_status(f"Results saved to: {output_file}")
        
        # displaying first 10 subdomains if found
        if unique_subdomains:
            print_status("Subdomains found:")
            for i, sub in enumerate(unique_subdomains[:10], 1):
                print(f"  {i}. {sub}")
            if len(unique_subdomains) > 10:
                print(f"  ... and {len(unique_subdomains) - 10} more")
        
        return unique_subdomains
        
    except subprocess.TimeoutExpired:
        print_status("Subfinder timed out after 5 minutes", "error")
        return []
    except Exception as e:
        print_status(f"Error running subfinder: {str(e)}", "error")
        return []
    


def run_httpx(subdomains_file, output_file):

    print_status(f"Probing for live hosts from: {subdomains_file}")
    
    # checking if input file exists and has content
    if not os.path.exists(subdomains_file):
        print_status(f"Input file {subdomains_file} not found ", "error")
        return []
    
    with open(subdomains_file, 'r') as f:
        subdomain_count = sum(1 for _ in f)
    
    if subdomain_count == 0:
        print_status("No subdomains to probe", "warning")
        return []
    
    # building httpx command
    cmd = [
        'httpx', 
        '-l', subdomains_file,
        '-silent',
        '-status-code',
        '-content-length',
        '-title',
        '-tech-detect',
        '-json',
        '-o', output_file
    ]
    
    try:
        print_status(f"Running httpx on {subdomain_count} subdomains")
        print_status(f"Command: {' '.join(cmd)}")  
        
        # executing httpx
        start_time = time.time()
        result = subprocess.run(cmd, 
                               capture_output=True, 
                               text=True, 
                               timeout=600)  # 10 minute timeout
        
        elapsed_time = time.time() - start_time
        
        if result.returncode != 0 and result.returncode != 1:  # httpx returns 1 for no results
            print_status(f"Httpx failed (code {result.returncode}): {result.stderr[:200]}", "error")
        
        # reading results from JSON output file
        live_hosts = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            live_hosts.append(data)
                        except json.JSONDecodeError:
                            # if not JSON format, assume it's a simple URL list
                            if line.startswith('http'):
                                live_hosts.append({'input': line, 'url': line})
        
        print_status(f"Found {len(live_hosts)} live hosts in {elapsed_time:.2f} seconds", "success")
        
        # displaying live hosts summary
        if live_hosts:
            print_status("Live hosts found:")
            for i, host in enumerate(live_hosts[:5], 1):
                if isinstance(host, dict):
                    url = host.get('url', host.get('input', 'N/A'))
                    status = host.get('status_code', 'N/A')
                    title = host.get('title', 'N/A')[:50]
                    print(f"  {i}. {url} [{status}] - {title}")
                else:
                    print(f"  {i}. {host}")
            
            if len(live_hosts) > 5:
                print(f"  ... and {len(live_hosts) - 5} more")
        
        return live_hosts
        
    except subprocess.TimeoutExpired:
        print_status("Httpx timed out after 10 minutes", "error")
        return []
    except Exception as e:
        print_status(f"Error running httpx: {str(e)}", "error")
        return []
    


def send_notification(domain, total_subdomains, live_hosts, webhook_url=platform_webhook, platform=platform):

    if not webhook_url:
        return False
    
    message = f"""
Subdomain Scan Complete!
• Target: {domain}
• Subdomains Found: {total_subdomains}
• Live Hosts: {live_hosts}
• Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    try:
        if platform == "telegram":

            # telegram notification
            import requests
            payload = {
                'chat_id': webhook_url.split('/')[-1],  # extracting chat ID
                'text': message,
                'parse_mode': 'HTML'
            }
            bot_token = webhook_url.split('/')[-2]
            url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
            response = requests.post(url, json=payload, timeout=10)
            
        elif platform == "discord":

            # discord notification
            import requests
            payload = {
                'content': message,
                'username': 'Subdomain Scanner'
            }
            response = requests.post(webhook_url, json=payload, timeout=10)
            
        elif platform == "slack":

            # slack notification
            import requests
            payload = {
                'text': message,
                'username': 'Subdomain Scanner',
                'icon_emoji': ':mag:'
            }
            response = requests.post(webhook_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            print_status("Notification sent successfully", "success")
            return True
        else:
            print_status(f"Failed to send notification: {response.status_code}", "warning")
            return False
            
    except ImportError:
        print_status("Requests library required for notifications. Install with: pip install requests", "warning")
        return False
    except Exception as e:
        print_status(f"Notification error: {str(e)}", "warning")
        return False

def main():
    
    # parsing command line arguments
    parser = argparse.ArgumentParser(
        description='Subdomain Enumeration and Live Host Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com -o ./scan_results
  %(prog)s -d example.com --notify telegram --webhook YOUR_WEBHOOK_URL
        """
    )
    
    parser.add_argument('-d', '--domain', 
                       required=True, 
                       help='Target domain to scan (e.g., example.com)')
    
    parser.add_argument('-o', '--output-dir', 
                       default='./results',
                       help='Output directory (default: ./results)')
    
    parser.add_argument('--notify',
                       choices=['telegram', 'discord', 'slack', 'none'],
                       default='none',
                       help='Send notifications via specified platform')
    
    parser.add_argument('--webhook',
                       help='Webhook URL for notifications')
    
    parser.add_argument('--skip-subfinder',
                       action='store_true',
                       help='Skip subfinder step (use existing subdomains file)')
    
    parser.add_argument('--skip-httpx',
                       action='store_true',
                       help='Skip httpx step')
    
    args = parser.parse_args()
    
    # creating output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # generating output file names
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    subdomains_file = output_dir / f"{args.domain}_{timestamp}_subdomains.txt"
    live_hosts_file = output_dir / f"{args.domain}_{timestamp}_live.json"
    report_file = output_dir / f"{args.domain}_{timestamp}_report.txt"
    
    print_status("=" * 60)
    print_status(f"Starting Subdomain Scanner")
    print_status(f"Target Domain: {args.domain}")
    print_status(f"Output Directory: {output_dir}")
    print_status("=" * 60)
    
    # checking if required tools are installed
    if not args.skip_subfinder and not check_tool_installed('subfinder'):
        print_status("subfinder is not installed or not in PATH", "error")
        print_status("Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "warning")
        sys.exit(1)
    
    if not args.skip_httpx and not check_tool_installed('httpx'):
        print_status("httpx is not installed or not in PATH", "error")
        print_status("Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "warning")
        sys.exit(1)
    
    subdomains = []
    live_hosts = []
    
    # 1. running subfinder
    if not args.skip_subfinder:
        subdomains = run_subfinder(args.domain, str(subdomains_file))
        
        if not subdomains:
            print_status("No subdomains found. Continuing anyway...", "warning")
    else:
        print_status("Skipping subfinder step", "info")
        # checking for existing subdomains file
        existing_files = list(output_dir.glob(f"{args.domain}_*_subdomains.txt"))
        if existing_files:
            # using the most recent file
            subdomains_file = sorted(existing_files)[-1]
            print_status(f"Using existing subdomains file: {subdomains_file}")
            with open(subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        else:
            print_status("No existing subdomains file found", "error")
            sys.exit(1)
    
    #  2. running httpx
    if not args.skip_httpx and subdomains:
        print("subdomain file name")
        print(subdomains_file)
        live_hosts = run_httpx(str(subdomains_file), str(live_hosts_file))
    elif args.skip_httpx:
        print_status("Skipping httpx step", "info")
    else:
        print_status("No subdomains to probe with httpx", "warning")
    
    # generating report
    try:
        with open(report_file, 'w') as f:
            f.write(f"Subdomain Scan Report\n")
            f.write(f"{'='*50}\n")
            f.write(f"Target Domain: {args.domain}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains Found: {len(subdomains)}\n")
            f.write(f"Total Live Hosts Found: {len(live_hosts)}\n")
            f.write(f"\nSubdomains File: {subdomains_file}\n")
            f.write(f"Live Hosts File: {live_hosts_file}\n")
            f.write(f"\n{'='*50}\n")
            
            if live_hosts:
                f.write("\nLIVE HOSTS DETAILS:\n")
                f.write("-" * 50 + "\n")
                for host in live_hosts:
                    if isinstance(host, dict):
                        url = host.get('url', host.get('input', 'N/A'))
                        status = host.get('status_code', 'N/A')
                        title = host.get('title', 'N/A')
                        tech = host.get('technologies', [])
                        f.write(f"URL: {url}\n")
                        f.write(f"Status: {status}\n")
                        f.write(f"Title: {title}\n")
                        if tech:
                            f.write(f"Technologies: {', '.join(tech)}\n")
                        f.write("-" * 30 + "\n")
        
        print_status(f"Report saved to: {report_file}", "success")
        
    except Exception as e:
        print_status(f"Error generating report: {str(e)}", "error")
    
    # sending notification 
    if args.notify != 'none' and args.webhook:
        print_status(f"Sending notification via {args.notify}...")
        send_notification(args.domain, len(subdomains), len(live_hosts), args.webhook, args.notify)

    elif args.notify != 'none' and args.webhook_url is None:
        # try to get webhook from environment if not specified
        env_var_name = f"{args.notify.upper()}_WEBHOOK"
        webhook_url = os.getenv(env_var_name)
        
        if webhook_url:
            print_status(f"Sending notification via {args.notify} (from environment)...")
            send_notification(args.domain, len(subdomains), len(live_hosts), webhook_url, args.notify)
        else:
            print_status(f"No webhook available for {args.notify}", "warning")
            print_status(f"Either pass --webhook URL or set {env_var_name} in environment", "info")
    
    print_status("=" * 60)
    print_status("Scan Complete!", "success")
    print_status(f"Subdomains: {len(subdomains)}")
    print_status(f"Live Hosts: {len(live_hosts)}")
    print_status(f"Files saved in: {output_dir}")
    print_status("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "warning")
        sys.exit(130)
    except Exception as e:
        print_status(f"Unexpected error: {str(e)}", "error")
        sys.exit(1)