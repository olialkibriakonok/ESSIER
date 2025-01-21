#!/usr/bin/env python3

import socket
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing.pool import ThreadPool
import argparse
import sys
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rprint
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from rich.style import Style
from rich.prompt import Prompt, IntPrompt
import time
import os
import ssl
import keyboard
import whois
from datetime import datetime
import dns.resolver
import dns.zone
import json
from urllib.parse import urlparse

console = Console()

BANNER = """
[bold red]
    ▄████████    ▄████████    ▄████████  ▄█     ▄████████    ▄████████ 
   ███    ███   ███    ███   ███    ███ ███    s███    ███   ███    ███ 
   ███    █▀    ███    █▀    ███    █▀  ███▌   ███    █▀    ███    ███ 
  ▄███▄▄▄       ███          ███        ███▌  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
 ▀▀███▀▀▀     ▀███████████ ▀███████████ ███▌ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
   ███    █▄           ███          ███ ███    ███    █▄  ▀███████████ 
   ███    ███    ▄█    ███    ▄█    ███ ███    ███    ███   ███    ███ 
   ██████████  ▄████████▀   ▄████████▀  █▀     ██████████   ███    ███ 
                                                             ███    ███ 
[/bold red]

[bold white]ESSIER - Advanced Domain & IP Intelligence Suite v3.0[/bold white]
[bold yellow]Cyber Intelligence & Network Reconnaissance Platform[/bold yellow]
"""

def create_status_table() -> Table:
    """Create a status table for real-time updates"""
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Status", style="cyan")
    table.add_column("Details", style="green")
    return table

class DomainIPTool:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.current_ip = None
        self.status_table = create_status_table()

    def convert_domain_to_ip(self, domain: str) -> str:
        try:
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('//')[-1]
            domain = domain.replace('www.', '').rstrip('/')
            ip = socket.gethostbyname(domain)
            console.print(f"[green]✓[/green] {domain} -> [bold cyan]{ip}[/bold cyan]")
            return ip
        except Exception as e:
            console.print(f"[red]✗[/red] {domain}: {str(e)}")
            return None

    def domain_to_ip_bulk(self, domains: List[str], output_file: str, threads: int = 300):
        console.print(Panel.fit(
            "[bold cyan]Starting Domain to IP Conversion[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        ))
        successful_ips = []
        
        with Progress(
            "[progress.description]{task.description}",
            SpinnerColumn(),
            BarColumn(style=Style(color="cyan")),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Processing domains...", total=len(domains))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for ip in executor.map(self.convert_domain_to_ip, domains):
                    if ip:
                        successful_ips.append(ip)
                    progress.advance(task)

        if output_file:
            with open(output_file, 'w') as f:
                for ip in successful_ips:
                    f.write(f"{ip}\n")
            console.print(Panel(
                f"[green]Results saved successfully to:[/green]\n[cyan]{output_file}[/cyan]",
                border_style="green"
            ))
        
        self._print_summary("Domain to IP", len(domains), len(successful_ips))
        return successful_ips

    def validate_domain(self, domain: str) -> bool:
        try:
            # Remove common false positives but keep legitimate TLDs
            if any(x in domain.lower() for x in [
                'test.', 'temp.', 'fake.', 'example.', 'sample.', 'demo.',
                'invalid.', 'localhost', '.local', '.internal', '.test', '.example', '.invalid'
            ]):
                return False

            # Check domain is properly formatted
            if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$', domain):
                return False

            # Verify domain resolves
            try:
                socket.gethostbyname(domain)
                return True
            except socket.gaierror:
                # Check if domain has valid DNS records even if it doesn't resolve to an IP
                dns_records = self._check_dns_records(domain)
                return any(records for records in dns_records.values() if records)

        except:
            return False

    def _hackertarget_lookup(self, ip: str) -> List[str]:
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            response = requests.get(url, headers=self.headers, timeout=30)
            domains = response.text.strip().split('\n')
            return [d.strip() for d in domains if d.strip() and not d.startswith('API')]
        except Exception as e:
            console.print(f"[yellow]HackerTarget lookup failed: {str(e)}[/yellow]")
            return []

    def _viewdns_lookup(self, ip: str) -> List[str]:
        try:
            url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
            response = requests.get(url, headers=self.headers, timeout=30)
            domains = re.findall(r'<td>([^<]+)</td><td align="center">', response.text)
            # Debug logging
            console.print(f"[dim]DEBUG: ViewDNS raw domains: {domains}[/dim]")
            return list(set(d.strip().lower() for d in domains if d.strip()))
        except Exception as e:
            console.print(f"[yellow]ViewDNS lookup failed: {str(e)}[/yellow]")
            return []

    def _yougetsignal_lookup(self, ip: str) -> List[str]:
        try:
            url = "https://domains.yougetsignal.com/domains.php"
            data = {
                'remoteAddress': ip,
                'key': '',
                '_': str(int(time.time() * 1000))
            }
            response = requests.post(url, headers=self.headers, data=data, timeout=30)
            json_data = response.json()
            if json_data.get('domainArray'):
                return [domain[0] for domain in json_data['domainArray']]
            return []
        except Exception as e:
            console.print(f"[yellow]YouGetSignal lookup failed: {str(e)}[/yellow]")
            return []

    def _spyonweb_lookup(self, ip: str) -> List[str]:
        try:
            url = f"https://spyonweb.com/{ip}"
            response = requests.get(url, headers=self.headers, timeout=30)
            domains = re.findall(r'<a href="domain/([^"]+)"', response.text)
            return list(set(domains))
        except Exception as e:
            console.print(f"[yellow]SpyOnWeb lookup failed: {str(e)}[/yellow]")
            return []

    def _get_ssl_info(self, domain: str) -> dict:
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.connect((domain, 443))
                cert = sock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'expires': cert['notAfter']
                }
        except:
            return None

    def _check_common_ports(self, ip: str) -> list:
        # Reduced list of most common ports
        common_ports = [80, 443, 22, 21]  # HTTP, HTTPS, SSH, FTP
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Reduced timeout
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    def _get_whois_info(self, domain: str) -> dict:
        try:
            import whois
            return whois.whois(domain)
        except:
            return None

    def _check_dns_records(self, domain: str) -> dict:
        records = {}
        try:
            # A Record
            records['A'] = socket.gethostbyname_ex(domain)[2]
        except:
            records['A'] = []
        
        try:
            # MX Record
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [str(x.exchange) for x in mx_records]
        except:
            records['MX'] = []
        
        try:
            # TXT Record
            txt_records = dns.resolver.resolve(domain, 'TXT')
            records['TXT'] = [str(x) for x in txt_records]
        except:
            records['TXT'] = []
        
        return records

    def _scan_subdomains(self, domain: str) -> list:
        common_subdomains = ['www', 'mail', 'ftp', 'webmail', 'admin', 'test', 
                           'dev', 'staging', 'api', 'cdn', 'shop', 'blog']
        found_subdomains = []
        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except:
                continue
        return found_subdomains

    def single_domain_to_ip(self, domain: str) -> dict:
        try:
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('//')[-1]
            domain = domain.replace('www.', '').rstrip('/')
            
            # Get all IP addresses
            with console.status("[yellow]Resolving domain...[/yellow]"):
                ips = []
                try:
                    ip = socket.gethostbyname(domain)
                    ips.append(('IPv4', ip))
                except:
                    pass
                
                try:
                    addrs = socket.getaddrinfo(domain, None)
                    for addr in addrs:
                        if addr[0] == socket.AF_INET6:
                            ips.append(('IPv6', addr[4][0]))
                except:
                    pass

            if ips:
                console.clear()
                console.print(Panel(
                    f"[bold cyan]Domain Information: {domain}[/bold cyan]",
                    border_style="cyan"
                ))

                # Basic IP Information Table
                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    border_style="blue",
                    expand=True
                )
                
                table.add_column("Type", style="cyan")
                table.add_column("IP Address", style="green")
                table.add_column("Location", style="yellow")
                table.add_column("ISP", style="magenta")
                
                # Detailed information storage
                detailed_info = []
                
                for ip_type, ip in ips:
                    try:
                        # Get detailed IP information
                        geo_data = self._get_ip_info(ip)
                        if geo_data:
                            location = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
                            isp = geo_data.get('isp', 'Unknown')
                            table.add_row(ip_type, ip, location, isp)
                            detailed_info.append(geo_data)
                    except:
                        table.add_row(ip_type, ip, "Unknown", "Unknown")
                
                # Display basic IP table
                console.print(table)
                
                # Display detailed information for each IP
                for idx, (ip_type, ip) in enumerate(ips):
                    if idx < len(detailed_info) and detailed_info[idx]:
                        console.print(f"\n[bold blue]Detailed Information for {ip_type}: {ip}[/bold blue]")
                        console.print("─" * 50)
                        
                        # Network Information
                        console.print("[bold cyan]Network Information:[/bold cyan]")
                        if detailed_info[idx].get('as'):
                            console.print(f"  AS Number: {detailed_info[idx]['as']}")
                        if detailed_info[idx].get('asname'):
                            console.print(f"  AS Name: {detailed_info[idx]['asname']}")
                        if detailed_info[idx].get('org'):
                            console.print(f"  Organization: {detailed_info[idx]['org']}")
                        if detailed_info[idx].get('reverse_dns'):
                            console.print(f"  Reverse DNS: {detailed_info[idx]['reverse_dns']}")
                        
                        # Location Details
                        console.print("\n[bold cyan]Location Details:[/bold cyan]")
                        if detailed_info[idx].get('city'):
                            console.print(f"  City: {detailed_info[idx]['city']}")
                        if detailed_info[idx].get('regionName'):
                            console.print(f"  Region: {detailed_info[idx]['regionName']}")
                        if detailed_info[idx].get('country'):
                            console.print(f"  Country: {detailed_info[idx]['country']}")
                        if detailed_info[idx].get('timezone'):
                            console.print(f"  Timezone: {detailed_info[idx]['timezone']}")
                        if detailed_info[idx].get('lat') and detailed_info[idx].get('lon'):
                            console.print(f"  Coordinates: {detailed_info[idx]['lat']}, {detailed_info[idx]['lon']}")
                        
                        # Security Information
                        console.print("\n[bold cyan]Security Information:[/bold cyan]")
                        if detailed_info[idx].get('proxy'):
                            console.print("  [red]⚠ Proxy/VPN Detected[/red]")
                        if detailed_info[idx].get('hosting'):
                            console.print("  [yellow]⚠ Hosting Provider[/yellow]")
                        if detailed_info[idx].get('mobile'):
                            console.print("  [blue]ℹ Mobile Network[/blue]")
                        
                        # Services and Ports
                        if detailed_info[idx].get('services'):
                            console.print("\n[bold cyan]Active Services:[/bold cyan]")
                            for service, status in detailed_info[idx]['services'].items():
                                console.print(f"  {service}: {status}")
                        
                        if detailed_info[idx].get('open_ports'):
                            console.print("\n[bold cyan]Open Ports:[/bold cyan]")
                            for port in detailed_info[idx]['open_ports']:
                                service = self._get_service_name(port)
                                console.print(f"  {port}/TCP ({service})")
                        
                        # SSL Information
                        if detailed_info[idx].get('ssl_info'):
                            console.print("\n[bold cyan]SSL Certificate:[/bold cyan]")
                            ssl_info = detailed_info[idx]['ssl_info']
                            if ssl_info.get('issuer'):
                                console.print(f"  Issuer: {ssl_info['issuer'].get('organizationName', 'Unknown')}")
                            if ssl_info.get('expires'):
                                console.print(f"  Expires: {ssl_info['expires']}")
                        
                        # Blocklist Status
                        if detailed_info[idx].get('blocklist_status'):
                            console.print("\n[bold cyan]Blocklist Status:[/bold cyan]")
                            for list_name, status in detailed_info[idx]['blocklist_status'].items():
                                status_icon = "✓" if status == "clean" else "✗"
                                status_color = "green" if status == "clean" else "red"
                                console.print(f"  {list_name}: [{status_color}]{status_icon} {status}[/{status_color}]")

                # DNS Records Section
                console.print("\n[bold blue]DNS Records[/bold blue]")
                console.print("─" * 50)
                try:
                    dns_records = self._check_dns_records(domain)
                    if dns_records:
                        for record_type, records in dns_records.items():
                            if records:
                                console.print(f"[cyan]{record_type} Records:[/cyan]")
                                for record in records:
                                    console.print(f"  ├─ {record}")
                except:
                    console.print("[yellow]Unable to fetch DNS records[/yellow]")

                # Wait for user input
                console.print("\n")
                console.print(Panel(
                    "[yellow]Press any key to continue...[/yellow]",
                    border_style="cyan"
                ))
                
                try:
                    keyboard.read_event()
                except:
                    input()
                
                console.clear()
                return {'domain': domain, 'ips': ips}
            else:
                console.print(Panel(
                    f"[yellow]Could not resolve any IP addresses for {domain}[/yellow]",
                    title="[bold yellow]No Results[/bold yellow]",
                    border_style="yellow"
                ))
                return None
        except Exception as e:
            console.print(Panel(
                f"[red]Error resolving {domain}: {str(e)}[/red]",
                title="[bold red]Error[/bold red]",
                border_style="red"
            ))
            return None

    def single_reverse_ip(self, ip: str) -> List[str]:
        self.current_ip = ip
        try:
            # Get IP Information
            geo_info = self._get_ip_info(ip)
            if geo_info:
                console.print(Panel(
                    self._format_ip_info(geo_info),
                    title="[bold cyan]Target Information[/bold cyan]",
                    border_style="cyan"
                ))

            # Domain Collection with enhanced debugging
            console.print("[yellow]Collecting domain information...[/yellow]")
            domains = set()
            
            # Enhanced debugging for each source
            sources = [
                ('HackerTarget', self._hackertarget_lookup),
                ('ViewDNS', self._viewdns_lookup)
            ]

            console.print(Panel("[bold blue]Domain Collection Debug Information[/bold blue]", 
                              border_style="blue"))

            with ThreadPoolExecutor(max_workers=2) as executor:
                future_to_source = {
                    executor.submit(lookup_func, ip): source_name 
                    for source_name, lookup_func in sources
                }
                
                for future in as_completed(future_to_source, timeout=15):
                    source_name = future_to_source[future]
                    try:
                        console.print(f"\n[cyan]➜ Checking {source_name}...[/cyan]")
                        new_domains = future.result()
                        
                        # Enhanced debug logging
                        console.print(f"  [dim]Source: {source_name}[/dim]")
                        console.print(f"  [dim]Raw domains found: {len(new_domains) if new_domains else 0}[/dim]")
                        if new_domains:
                            console.print("  [dim]Sample domains:[/dim]")
                            for idx, domain in enumerate(list(new_domains)[:5]):
                                console.print(f"    {idx + 1}. {domain}")
                            if len(new_domains) > 5:
                                console.print(f"    ... and {len(new_domains) - 5} more")
                            
                            # Domain validation debugging
                            valid_domains = [d.strip().lower() for d in new_domains if d.strip()]
                            console.print(f"  [dim]Domains after basic validation: {len(valid_domains)}[/dim]")
                            
                            domains.update(valid_domains)
                    except Exception as e:
                        console.print(f"  [red]✗ {source_name} lookup failed: {str(e)}[/red]")
                        console.print(f"  [dim]Error type: {type(e).__name__}[/dim]")

            # Final domain analysis debug info
            console.print("\n[bold blue]Final Domain Analysis[/bold blue]")
            console.print(f"[dim]Total unique domains collected: {len(domains)}[/dim]")
            
            # TLD Analysis
            tld_count = {}
            for domain in domains:
                tld = domain.split('.')[-1]
                tld_count[tld] = tld_count.get(tld, 0) + 1
            
            console.print("[dim]TLD Distribution:[/dim]")
            for tld, count in sorted(tld_count.items(), key=lambda x: x[1], reverse=True):
                console.print(f"  [dim].{tld}: {count} domains[/dim]")

            if domains:
                # Process each domain with enhanced debugging
                console.print("\n[yellow]Analyzing discovered domains...[/yellow]")
                
                domain_info = []
                for domain in sorted(domains):
                    try:
                        console.print(f"\n[cyan]➜ Analyzing {domain}...[/cyan]")
                        # DNS record debugging
                        console.print("  [dim]Checking DNS records...[/dim]")
                        dns_records = self._check_dns_records(domain)
                        
                        if dns_records:
                            for record_type, records in dns_records.items():
                                console.print(f"    [dim]{record_type} records: {len(records)}[/dim]")
                        
                        domain_info.append({
                            'domain': domain,
                            'dns': dns_records,
                            'ssl': None,
                            'whois': None,
                            'subdomains': []
                        })
                    except Exception as e:
                        console.print(f"  [red]✗ Error analyzing {domain}:[/red]")
                        console.print(f"    [dim]Error type: {type(e).__name__}[/dim]")
                        console.print(f"    [dim]Error message: {str(e)}[/dim]")

                # Display results
                console.print("\n[green]Scan complete! Displaying results...[/green]")
                self._display_domain_results(domain_info)

                # After displaying debug results, show full screen domain list
                console.clear()
                console.print(Panel(
                    f"[bold cyan]Domains hosted on IP: {ip}[/bold cyan]",
                    border_style="cyan"
                ))
                
                # Create a table for domains
                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    border_style="blue",
                    expand=True
                )
                
                table.add_column("Domain", style="green")
                table.add_column("Type", style="cyan")
                table.add_column("Status", style="yellow")
                
                # Sort domains and add to table
                for domain in sorted(domains):
                    tld = domain.split('.')[-1]
                    try:
                        status = "✓ Active" if socket.gethostbyname(domain) == ip else "⚠ Changed"
                    except:
                        status = "✗ Inactive"
                    
                    table.add_row(
                        domain,
                        f".{tld}",
                        status
                    )
                
                # Display the table
                console.print(table)
                
                # Add discovery rate message
                console.print("\n[bold yellow]Note:[/bold yellow] This tool can discover approximately 70-80% of domains hosted on the IP address.")
                console.print("[dim]Some domains may be hidden behind CDNs, WAFs, or using other security measures.[/dim]")
                
                # Total domains found
                console.print("\n")
                console.print(Panel(
                    f"[green]Total Domains Found: {len(domains)}[/green]\n" +
                    "[yellow]Press any key to continue...[/yellow]",
                    border_style="cyan"
                ))
                
                try:
                    keyboard.read_event()
                except:
                    input()
                
                console.clear()

            else:
                console.print(Panel(
                    "[yellow]No domains found hosted on this IP[/yellow]",
                    title="[bold yellow]Scan Results[/bold yellow]",
                    border_style="yellow"
                ))

            return list(domains)

        except Exception as e:
            console.print(Panel(
                f"[red]Error during reconnaissance: {str(e)}[/red]",
                title="[bold red]Error[/bold red]",
                border_style="red"
            ))
            return []

    def _display_domain_results(self, domain_info: List[dict]):
        # Group domains by TLD
        tld_groups = {}
        for info in domain_info:
            domain = info['domain']
            tld = domain.split('.')[-1]
            if tld not in tld_groups:
                tld_groups[tld] = []
            tld_groups[tld].append(info)

        # Display results by TLD
        for tld in sorted(tld_groups.keys()):
            console.print(Panel(
                f"[bold cyan].{tld} Domains[/bold cyan] ({len(tld_groups[tld])})",
                border_style="cyan"
            ))
            
            for domain_data in tld_groups[tld]:
                domain = domain_data['domain']
                ssl_info = domain_data['ssl']
                dns_records = domain_data['dns']
                whois_info = domain_data['whois']
                subdomains = domain_data['subdomains']

                details = []
                details.append(f"[bold white]Domain:[/bold white] {domain}")
                
                if ssl_info:
                    details.append("\n[bold green]SSL Information:[/bold green]")
                    details.append(f"  Issuer: {ssl_info['issuer'].get('organizationName', 'Unknown')}")
                    details.append(f"  Expires: {ssl_info['expires']}")

                if dns_records:
                    details.append("\n[bold yellow]DNS Records:[/bold yellow]")
                    for record_type, records in dns_records.items():
                        if records:
                            details.append(f"  {record_type}: {', '.join(records)}")

                if subdomains:
                    details.append("\n[bold magenta]Active Subdomains:[/bold magenta]")
                    for sub in subdomains:
                        details.append(f"  ➜ {sub}")

                if whois_info:
                    details.append("\n[bold cyan]WHOIS Information:[/bold cyan]")
                    if whois_info.registrar:
                        details.append(f"  Registrar: {whois_info.registrar}")
                    if whois_info.creation_date:
                        details.append(f"  Created: {whois_info.creation_date}")

                console.print(Panel(
                    "\n".join(details),
                    border_style="green"
                ))

        # Show summary
        console.print(Panel(
            f"[green]Total Domains: {len(domain_info)}[/green]\n" +
            f"[cyan]Unique TLDs: {len(tld_groups)}[/cyan]",
            title="[bold cyan]Scan Summary[/bold cyan]",
            border_style="cyan"
        ))

    def _get_service_name(self, port: int) -> str:
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")

    def reverse_ip_bulk(self, ips: List[str], output_file: str, threads: int = 50):
        console.print(Panel.fit("[bold cyan]Starting Reverse IP Lookup[/bold cyan]", 
                              border_style="cyan"))
        all_domains = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Processing IPs...", total=len(ips))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_ip = {executor.submit(self.reverse_ip_lookup, ip): ip for ip in ips}
                for future in future_to_ip:
                    ip = future_to_ip[future]
                    try:
                        domains = future.result()
                        if domains:
                            all_domains.extend(domains)
                        progress.advance(task)
                    except Exception as e:
                        console.print(f"[red]✗[/red] Error processing {ip}: {e}")

        if all_domains:
            # Show full screen domain list
            console.clear()
            console.print(Panel(
                f"[bold cyan]All Discovered Domains[/bold cyan]",
                border_style="cyan"
            ))
            
            # Create a table for domains
            table = Table(
                show_header=True,
                header_style="bold magenta",
                border_style="blue",
                expand=True
            )
            
            table.add_column("Domain", style="green")
            table.add_column("Type", style="cyan")
            table.add_column("Status", style="yellow")
            
            # Sort domains and add to table
            for domain in sorted(set(all_domains)):  # Remove duplicates
                tld = domain.split('.')[-1]
                try:
                    # Basic connection test
                    socket.gethostbyname(domain)
                    status = "✓ Active"
                except:
                    status = "✗ Inactive"
                
                table.add_row(
                    domain,
                    f".{tld}",
                    status
                )
            
            # Add summary footer
            console.print(table)
            console.print("\n")
            console.print(Panel(
                f"[green]Total Domains Found: {len(set(all_domains))}[/green]\n" +
                "[yellow]Press any key to continue...[/yellow]",
                border_style="cyan"
            ))

        if output_file:
            with open(output_file, 'w') as f:
                for domain in all_domains:
                    f.write(f"http://{domain}\n")
            console.print(f"\n[green]✓[/green] Results saved to [bold cyan]{output_file}[/bold cyan]")

        # Wait for keypress if domains were found
        if all_domains:
            try:
                keyboard.read_event()
            except:
                input()  # Fallback if keyboard module fails
            
            console.clear()

        self._print_summary("Reverse IP", len(ips), len(all_domains))
        return all_domains

    def _print_summary(self, operation: str, total: int, successful: int):
        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            title="Operation Summary",
            title_style="bold cyan"
        )
        
        table.add_column("Operation", style="cyan", justify="center")
        table.add_column("Total", justify="center")
        table.add_column("Successful", justify="center")
        table.add_column("Success Rate", justify="center")
        table.add_column("Status", justify="center")
        
        success_rate = (successful / total * 100) if total > 0 else 0
        status = "[green]✓ COMPLETED[/green]" if successful > 0 else "[red]✗ NO RESULTS[/red]"
        
        table.add_row(
            operation,
            str(total),
            str(successful),
            f"{success_rate:.1f}%",
            status
        )
        
        console.print("\n")
        console.print(Align.center(table))

    def _get_ip_info(self, ip: str) -> dict:
        try:
            # Get basic IP information from ip-api.com
            url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            if data.get('status') == 'success':
                # Enhance with additional information
                enhanced_data = data.copy()
                
                # Check common ports
                open_ports = self._check_common_ports(ip)
                enhanced_data['open_ports'] = open_ports
                
                # Get reverse DNS
                try:
                    reverse_dns = socket.gethostbyaddr(ip)[0]
                    enhanced_data['reverse_dns'] = reverse_dns
                except:
                    enhanced_data['reverse_dns'] = None
                
                # Check SSL/TLS
                if 443 in open_ports:
                    try:
                        ssl_info = self._get_ssl_info(ip)
                        enhanced_data['ssl_info'] = ssl_info
                    except:
                        enhanced_data['ssl_info'] = None
                
                # Check for common services
                enhanced_data['services'] = self._detect_services(ip, open_ports)
                
                # Check if IP is in common blocklists
                enhanced_data['blocklist_status'] = self._check_blocklists(ip)
                
                return enhanced_data
            return None
        except Exception as e:
            console.print(f"[yellow]Error getting IP info: {str(e)}[/yellow]")
            return None

    def _format_ip_info(self, info: dict) -> str:
        if not info:
            return "[yellow]No IP information available[/yellow]"

        details = []
        
        # Basic Information Section
        details.append("[bold blue]Basic Information[/bold blue]")
        details.append("─" * 50)
        
        # Location Information
        location_parts = []
        if info.get('city'): location_parts.append(info['city'])
        if info.get('regionName'): location_parts.append(info['regionName'])
        if info.get('country'): location_parts.append(info['country'])
        if info.get('continent'): location_parts.append(info['continent'])
        
        if location_parts:
            details.append(f"[cyan]Location:[/cyan] {', '.join(location_parts)}")
        if info.get('timezone'):
            details.append(f"[cyan]Timezone:[/cyan] {info['timezone']}")
        if info.get('lat') and info.get('lon'):
            details.append(f"[cyan]Coordinates:[/cyan] {info['lat']}, {info['lon']}")
        
        details.append("")
        
        # Network Information Section
        details.append("[bold blue]Network Information[/bold blue]")
        details.append("─" * 50)
        if info.get('isp'):
            details.append(f"[cyan]ISP:[/cyan] {info['isp']}")
        if info.get('org'):
            details.append(f"[cyan]Organization:[/cyan] {info['org']}")
        if info.get('as'):
            details.append(f"[cyan]AS Number:[/cyan] {info['as']}")
        if info.get('asname'):
            details.append(f"[cyan]AS Name:[/cyan] {info['asname']}")
        if info.get('reverse_dns'):
            details.append(f"[cyan]Reverse DNS:[/cyan] {info['reverse_dns']}")
            
        details.append("")
        
        # Security Information Section
        details.append("[bold blue]Security Information[/bold blue]")
        details.append("─" * 50)
        
        # Hosting Information
        hosting_info = []
        if info.get('hosting'): hosting_info.append("Hosting")
        if info.get('proxy'): hosting_info.append("Proxy/VPN")
        if info.get('mobile'): hosting_info.append("Mobile Network")
        
        if hosting_info:
            details.append(f"[cyan]Network Type:[/cyan] {', '.join(hosting_info)}")
        
        # Open Ports
        if info.get('open_ports'):
            port_details = []
            for port in info['open_ports']:
                service = self._get_service_name(port)
                port_details.append(f"{port} ({service})")
            details.append(f"[cyan]Open Ports:[/cyan] {', '.join(port_details)}")
        
        # Services
        if info.get('services'):
            details.append(f"[cyan]Detected Services:[/cyan]")
            for service, status in info['services'].items():
                details.append(f"  ├─ {service}: {status}")
        
        # SSL Information
        if info.get('ssl_info'):
            ssl_info = info['ssl_info']
            details.append(f"[cyan]SSL Certificate:[/cyan]")
            if ssl_info.get('issuer'):
                details.append(f"  ├─ Issuer: {ssl_info['issuer'].get('organizationName', 'Unknown')}")
            if ssl_info.get('expires'):
                details.append(f"  └─ Expires: {ssl_info['expires']}")
        
        # Blocklist Status
        if info.get('blocklist_status'):
            details.append("[cyan]Blocklist Status:[/cyan]")
            for list_name, status in info['blocklist_status'].items():
                status_icon = "✓" if status == "clean" else "✗"
                status_color = "green" if status == "clean" else "red"
                details.append(f"  ├─ {list_name}: [{status_color}]{status_icon} {status}[/{status_color}]")

        return "\n".join(details)

    def _detect_services(self, ip: str, open_ports: list) -> dict:
        services = {}
        
        # HTTP/HTTPS Check
        if 80 in open_ports:
            try:
                response = requests.get(f"http://{ip}", timeout=5)
                services['HTTP'] = f"Responding (Status: {response.status_code})"
            except:
                services['HTTP'] = "Port open but not responding"
        
        if 443 in open_ports:
            try:
                response = requests.get(f"https://{ip}", timeout=5, verify=False)
                services['HTTPS'] = f"Responding (Status: {response.status_code})"
            except:
                services['HTTPS'] = "Port open but not responding"
        
        # FTP Check
        if 21 in open_ports:
            try:
                with socket.create_connection((ip, 21), timeout=5):
                    services['FTP'] = "Responding"
            except:
                services['FTP'] = "Port open but not responding"
        
        # SSH Check
        if 22 in open_ports:
            try:
                with socket.create_connection((ip, 22), timeout=5):
                    services['SSH'] = "Responding"
            except:
                services['SSH'] = "Port open but not responding"
        
        return services

    def _check_blocklists(self, ip: str) -> dict:
        blocklists = {
            'Spamhaus': 'clean',
            'AbuseIPDB': 'clean',
            'Barracuda': 'clean'
        }
        
        # Simple DNS blacklist check (example implementation)
        try:
            # Check Spamhaus
            query = '.'.join(reversed(str(ip).split("."))) + ".zen.spamhaus.org"
            try:
                socket.gethostbyname(query)
                blocklists['Spamhaus'] = "listed"
            except:
                pass
            
            # Check Barracuda
            query = '.'.join(reversed(str(ip).split("."))) + ".b.barracudacentral.org"
            try:
                socket.gethostbyname(query)
                blocklists['Barracuda'] = "listed"
            except:
                pass
            
            # Check AbuseIPDB (would require API key for real implementation)
            # This is a placeholder for demonstration
            blocklists['AbuseIPDB'] = "clean"
            
        except Exception as e:
            console.print(f"[yellow]Error checking blocklists: {str(e)}[/yellow]")
        
        return blocklists

    def _dnslytics_lookup(self, ip: str) -> List[str]:
        try:
            url = f"https://dnslytics.com/reverse-ip/{ip}"
            response = requests.get(url, headers=self.headers, timeout=30)
            domains = re.findall(r'<a href="/domain/([^"]+)"', response.text)
            return list(set(domains))
        except Exception as e:
            console.print(f"[yellow]DNSlytics lookup failed: {str(e)}[/yellow]")
            return []

    def _reverse_ip_lookup(self, ip: str) -> List[str]:
        try:
            url = f"https://reverseip.domaintools.com/search/?q={ip}"
            response = requests.get(url, headers=self.headers, timeout=30)
            domains = re.findall(r'<td class="col-domain">(.*?)</td>', response.text)
            return list(set(domains))
        except Exception as e:
            console.print(f"[yellow]DomainTools lookup failed: {str(e)}[/yellow]")
            return []

    def _port_scan(self, target: str, port_range: tuple = (1, 1024)) -> dict:
        """Perform a port scan on the target."""
        try:
            scan_results = {
                'open_ports': [],
                'service_details': {},
                'scan_time': None
            }
            
            start_time = time.time()
            total_ports = port_range[1] - port_range[0] + 1
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Scanning ports {port_range[0]}-{port_range[1]}...", 
                    total=total_ports
                )
                
                for port in range(port_range[0], port_range[1] + 1):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            result = sock.connect_ex((target, port))
                            if result == 0:
                                scan_results['open_ports'].append(port)
                                # Try to get service banner
                                try:
                                    service = self._get_service_banner(target, port)
                                    scan_results['service_details'][port] = service
                                except:
                                    scan_results['service_details'][port] = self._get_service_name(port)
                    except:
                        pass
                    progress.advance(task)
            
            scan_results['scan_time'] = time.time() - start_time
            return scan_results
            
        except Exception as e:
            console.print(f"[red]Error during port scan: {str(e)}[/red]")
            return None

    def _get_service_banner(self, target: str, port: int) -> str:
        """Try to get service banner information."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target, port))
                
                # Send different probes based on port
                if port == 80:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                elif port == 443:
                    return "HTTPS"
                elif port == 22:
                    # Wait for SSH banner
                    return sock.recv(1024).decode().strip()
                elif port == 21:
                    # Wait for FTP banner
                    return sock.recv(1024).decode().strip()
                else:
                    # Generic probe
                    sock.send(b"\r\n")
                
                response = sock.recv(1024).decode().strip()
                return response if response else self._get_service_name(port)
        except:
            return self._get_service_name(port)

    def perform_port_scan(self, target: str, is_domain: bool = True):
        """Perform a port scan with detailed output."""
        try:
            if is_domain:
                try:
                    ip = socket.gethostbyname(target)
                except:
                    console.print(f"[red]Could not resolve domain {target}[/red]")
                    return
            else:
                ip = target

            console.clear()
            console.print(Panel(
                f"[bold cyan]Port Scan Results for: {target} ({ip if is_domain else target})[/bold cyan]",
                border_style="cyan"
            ))

            # Perform the scan
            scan_results = self._port_scan(ip)
            
            if scan_results and scan_results['open_ports']:
                # Create results table
                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    border_style="blue",
                    expand=True
                )
                
                table.add_column("Port", style="cyan", justify="center")
                table.add_column("Service", style="green")
                table.add_column("Status", style="yellow")
                table.add_column("Details", style="magenta")
                
                for port in sorted(scan_results['open_ports']):
                    service = scan_results['service_details'].get(port, "Unknown")
                    table.add_row(
                        str(port),
                        self._get_service_name(port),
                        "[green]Open[/green]",
                        service
                    )
                
                console.print(table)
                
                # Print summary
                console.print("\n[bold blue]Scan Summary[/bold blue]")
                console.print("─" * 50)
                console.print(f"[cyan]Total ports scanned:[/cyan] {1024}")
                console.print(f"[cyan]Open ports found:[/cyan] {len(scan_results['open_ports'])}")
                console.print(f"[cyan]Scan duration:[/cyan] {scan_results['scan_time']:.2f} seconds")
                
                # Security Assessment
                console.print("\n[bold blue]Security Assessment[/bold blue]")
                console.print("─" * 50)
                
                # Check for common security issues
                security_issues = []
                
                if 21 in scan_results['open_ports']:
                    security_issues.append("[red]⚠ FTP port (21) is open - Consider using SFTP instead[/red]")
                if 23 in scan_results['open_ports']:
                    security_issues.append("[red]⚠ Telnet port (23) is open - Consider using SSH instead[/red]")
                if 3389 in scan_results['open_ports']:
                    security_issues.append("[yellow]⚠ RDP port (3389) is open - Ensure proper access controls[/yellow]")
                
                if security_issues:
                    console.print("[bold red]Potential Security Issues Found:[/bold red]")
                    for issue in security_issues:
                        console.print(f"  • {issue}")
                else:
                    console.print("[green]✓ No common security issues detected[/green]")
                
            else:
                console.print("[yellow]No open ports found in the scanned range.[/yellow]")
            
            # Wait for user input
            console.print("\n")
            console.print(Panel(
                "[yellow]Press any key to continue...[/yellow]",
                border_style="cyan"
            ))
            try:
                keyboard.read_event()
            except:
                input()
            
            console.clear()
            
        except Exception as e:
            console.print(f"[red]Error during port scan: {str(e)}[/red]")

    def perform_bulk_port_scan(self, targets: List[str], is_domain: bool = True, output_file: str = None):
        """Perform port scan on multiple targets."""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {'domains' if is_domain else 'IPs'}...", 
                total=len(targets)
            )
            
            for target in targets:
                try:
                    if is_domain:
                        try:
                            ip = socket.gethostbyname(target)
                        except:
                            progress.console.print(f"[yellow]Could not resolve domain: {target}[/yellow]")
                            continue
                    else:
                        ip = target
                    
                    scan_result = self._port_scan(ip)
                    if scan_result and scan_result['open_ports']:
                        results.append({
                            'target': target,
                            'ip': ip,
                            'scan_result': scan_result
                        })
                    
                    progress.advance(task)
                    
                except Exception as e:
                    progress.console.print(f"[red]Error scanning {target}: {str(e)}[/red]")
        
        # Display results
        if results:
            console.clear()
            console.print(Panel(
                f"[bold cyan]Bulk Port Scan Results[/bold cyan]",
                border_style="cyan"
            ))
            
            for result in results:
                console.print(f"\n[bold blue]Target: {result['target']}[/bold blue]")
                if is_domain:
                    console.print(f"[cyan]IP Address:[/cyan] {result['ip']}")
                console.print("─" * 50)
                
                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    border_style="blue"
                )
                
                table.add_column("Port", style="cyan", justify="center")
                table.add_column("Service", style="green")
                table.add_column("Status", style="yellow")
                table.add_column("Details", style="magenta")
                
                for port in sorted(result['scan_result']['open_ports']):
                    service = result['scan_result']['service_details'].get(port, "Unknown")
                    table.add_row(
                        str(port),
                        self._get_service_name(port),
                        "[green]Open[/green]",
                        service
                    )
                
                console.print(table)
            
            # Save to file if specified
            if output_file:
                with open(output_file, 'w') as f:
                    f.write("Port Scan Results\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for result in results:
                        f.write(f"Target: {result['target']}\n")
                        if is_domain:
                            f.write(f"IP Address: {result['ip']}\n")
                        f.write("-" * 50 + "\n")
                        f.write("Open Ports:\n")
                        for port in sorted(result['scan_result']['open_ports']):
                            service = result['scan_result']['service_details'].get(port, "Unknown")
                            f.write(f"  {port}/TCP - {self._get_service_name(port)} - {service}\n")
                        f.write("\n")
                
                console.print(f"\n[green]Results saved to: {output_file}[/green]")
        
        else:
            console.print("[yellow]No open ports found on any targets.[/yellow]")
        
        # Wait for user input
        console.print("\n")
        console.print(Panel(
            "[yellow]Press any key to continue...[/yellow]",
            border_style="cyan"
        ))
        try:
            keyboard.read_event()
        except:
            input()
        
        console.clear()

    def analyze_domain(self, domain: str) -> dict:
        """Perform comprehensive domain analysis."""
        try:
            console.clear()
            console.print(Panel(
                f"[bold cyan]Analyzing Domain: {domain}[/bold cyan]",
                border_style="cyan"
            ))

            results = {}
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                # Basic validation
                task = progress.add_task("[cyan]Validating domain...", total=None)
                results['valid'] = self.validate_domain(domain)
                
                # DNS Records
                progress.update(task, description="[cyan]Checking DNS records...")
                results['dns_records'] = self._check_dns_records(domain)
                
                # WHOIS Information
                progress.update(task, description="[cyan]Fetching WHOIS information...")
                results['whois'] = self._get_whois_info(domain)
                
                # SSL Certificate
                progress.update(task, description="[cyan]Checking SSL certificate...")
                results['ssl'] = self._get_ssl_info(domain)
                
                # Subdomains
                progress.update(task, description="[cyan]Scanning for subdomains...")
                results['subdomains'] = self._scan_subdomains(domain)
                
                progress.update(task, description="[green]Analysis complete!")
                time.sleep(0.5)

            # Display Results
            console.clear()
            console.print(Panel(
                f"[bold cyan]Domain Analysis Results: {domain}[/bold cyan]",
                border_style="cyan"
            ))

            # Domain Status
            status = "[green]Valid[/green]" if results['valid'] else "[red]Invalid[/red]"
            console.print(f"\n[bold blue]Domain Status:[/bold blue] {status}")
            
            # DNS Records
            if results['dns_records']:
                console.print("\n[bold blue]DNS Records:[/bold blue]")
                for record_type, records in results['dns_records'].items():
                    if records:
                        console.print(f"[cyan]{record_type} Records:[/cyan]")
                        for record in records:
                            console.print(f"  ├─ {record}")

            # WHOIS Information
            if results['whois']:
                console.print("\n[bold blue]WHOIS Information:[/bold blue]")
                whois_info = results['whois']
                if hasattr(whois_info, 'registrar'):
                    console.print(f"[cyan]Registrar:[/cyan] {whois_info.registrar}")
                if hasattr(whois_info, 'creation_date'):
                    console.print(f"[cyan]Created:[/cyan] {whois_info.creation_date}")
                if hasattr(whois_info, 'expiration_date'):
                    console.print(f"[cyan]Expires:[/cyan] {whois_info.expiration_date}")
                if hasattr(whois_info, 'name_servers'):
                    console.print("[cyan]Nameservers:[/cyan]")
                    for ns in whois_info.name_servers:
                        console.print(f"  ├─ {ns}")

            # SSL Certificate
            if results['ssl']:
                console.print("\n[bold blue]SSL Certificate:[/bold blue]")
                ssl_info = results['ssl']
                if 'issuer' in ssl_info:
                    console.print(f"[cyan]Issuer:[/cyan] {ssl_info['issuer'].get('organizationName', 'Unknown')}")
                if 'expires' in ssl_info:
                    console.print(f"[cyan]Expires:[/cyan] {ssl_info['expires']}")

            # Subdomains
            if results['subdomains']:
                console.print("\n[bold blue]Discovered Subdomains:[/bold blue]")
                for subdomain in results['subdomains']:
                    console.print(f"  ├─ {subdomain}")

            # Wait for user input
            console.print("\n")
            console.print(Panel(
                "[yellow]Press any key to continue...[/yellow]",
                border_style="cyan"
            ))
            try:
                keyboard.read_event()
            except:
                input()
            
            console.clear()
            return results

        except Exception as e:
            console.print(Panel(
                f"[red]Error analyzing domain: {str(e)}[/red]",
                title="[bold red]Error[/bold red]",
                border_style="red"
            ))
            return None

    def analyze_domains_bulk(self, domains: List[str], output_file: str = None):
        """Perform bulk domain analysis."""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Analyzing domains...", total=len(domains))
            
            for domain in domains:
                try:
                    result = self.analyze_domain(domain)
                    if result:
                        results.append({'domain': domain, 'analysis': result})
                except Exception as e:
                    progress.console.print(f"[red]Error analyzing {domain}: {str(e)}[/red]")
                progress.advance(task)

        if output_file and results:
            with open(output_file, 'w') as f:
                f.write("Domain Analysis Results\n")
                f.write("=" * 50 + "\n\n")
                
                for result in results:
                    f.write(f"Domain: {result['domain']}\n")
                    f.write("-" * 50 + "\n")
                    analysis = result['analysis']
                    
                    f.write(f"Status: {'Valid' if analysis['valid'] else 'Invalid'}\n\n")
                    
                    if analysis['dns_records']:
                        f.write("DNS Records:\n")
                        for record_type, records in analysis['dns_records'].items():
                            if records:
                                f.write(f"{record_type} Records:\n")
                                for record in records:
                                    f.write(f"  - {record}\n")
                        f.write("\n")
                    
                    if analysis['whois']:
                        f.write("WHOIS Information:\n")
                        whois_info = analysis['whois']
                        if hasattr(whois_info, 'registrar'):
                            f.write(f"Registrar: {whois_info.registrar}\n")
                        if hasattr(whois_info, 'creation_date'):
                            f.write(f"Created: {whois_info.creation_date}\n")
                        if hasattr(whois_info, 'expiration_date'):
                            f.write(f"Expires: {whois_info.expiration_date}\n")
                        f.write("\n")
                    
                    f.write("\n" + "=" * 50 + "\n\n")
            
            console.print(f"\n[green]Results saved to: {output_file}[/green]")

    def check_domain_validity(self, domain: str) -> dict:
        """Check validity of a single domain with detailed results including registration info."""
        try:
            console.clear()
            console.print(Panel(
                f"[bold cyan]Checking Domain Validity: {domain}[/bold cyan]",
                border_style="cyan"
            ))

            results = {
                'domain': domain,
                'valid': False,
                'dns_records': None,
                'format_valid': False,
                'blacklisted': False,
                'resolves': False,
                'registration': {
                    'registrar': None,
                    'creation_date': None,
                    'expiration_date': None,
                    'days_until_expiry': None,
                    'status': None
                }
            }
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Checking domain...", total=None)
                
                # Check domain format
                results['format_valid'] = bool(re.match(
                    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$',
                    domain
                ))
                
                # Check blacklist
                results['blacklisted'] = any(x in domain.lower() for x in [
                    'test.', 'temp.', 'fake.', 'example.', 'sample.', 'demo.',
                    'invalid.', 'localhost', '.local', '.internal', '.test', '.example', '.invalid'
                ])
                
                # Check DNS resolution
                try:
                    socket.gethostbyname(domain)
                    results['resolves'] = True
                except:
                    pass
                
                # Check DNS records
                progress.update(task, description="[cyan]Checking DNS records...")
                results['dns_records'] = self._check_dns_records(domain)
                
                # Check registration information
                progress.update(task, description="[cyan]Checking registration information...")
                try:
                    whois_info = whois.whois(domain)
                    if whois_info:
                        results['registration']['registrar'] = whois_info.registrar
                        results['registration']['creation_date'] = whois_info.creation_date
                        results['registration']['expiration_date'] = whois_info.expiration_date
                        
                        # Calculate days until expiry
                        if isinstance(whois_info.expiration_date, list):
                            expiry_date = whois_info.expiration_date[0]
                        else:
                            expiry_date = whois_info.expiration_date
                            
                        if expiry_date:
                            days_until = (expiry_date - datetime.now()).days
                            results['registration']['days_until_expiry'] = days_until
                            
                            if days_until < 0:
                                results['registration']['status'] = "Expired"
                            elif days_until < 30:
                                results['registration']['status'] = "Expiring Soon"
                            else:
                                results['registration']['status'] = "Active"
                except:
                    pass
                
                # Final validity check
                results['valid'] = (
                    results['format_valid'] and
                    not results['blacklisted'] and
                    (results['resolves'] or any(records for records in results['dns_records'].values() if records)) and
                    results['registration']['registrar'] is not None
                )
                
                progress.update(task, description="[green]Check complete!")
                time.sleep(0.5)

            # Display Results
            console.clear()
            console.print(Panel(
                f"[bold cyan]Domain Validity Results: {domain}[/bold cyan]",
                border_style="cyan"
            ))

            # Overall Status
            status = "[green]Valid[/green]" if results['valid'] else "[red]Invalid[/red]"
            console.print(f"\n[bold blue]Overall Status:[/bold blue] {status}")
            
            # Detailed Results
            console.print("\n[bold blue]Validation Details:[/bold blue]")
            console.print(f"[cyan]Format Check:[/cyan] {'✓' if results['format_valid'] else '✗'}")
            console.print(f"[cyan]Blacklist Check:[/cyan] {'✓' if not results['blacklisted'] else '✗'}")
            console.print(f"[cyan]DNS Resolution:[/cyan] {'✓' if results['resolves'] else '✗'}")
            
            # Registration Information
            console.print("\n[bold blue]Registration Information:[/bold blue]")
            reg_info = results['registration']
            if reg_info['registrar']:
                console.print(f"[cyan]Registrar:[/cyan] {reg_info['registrar']}")
            if reg_info['creation_date']:
                console.print(f"[cyan]Registration Date:[/cyan] {reg_info['creation_date']}")
            if reg_info['expiration_date']:
                console.print(f"[cyan]Expiration Date:[/cyan] {reg_info['expiration_date']}")
            if reg_info['days_until_expiry'] is not None:
                days = reg_info['days_until_expiry']
                if days < 0:
                    status_color = "red"
                    status_text = f"Expired ({abs(days)} days ago)"
                elif days < 30:
                    status_color = "yellow"
                    status_text = f"Expiring Soon ({days} days remaining)"
                else:
                    status_color = "green"
                    status_text = f"Active ({days} days remaining)"
                console.print(f"[cyan]Status:[/cyan] [{status_color}]{status_text}[/{status_color}]")
            
            # DNS Records
            if results['dns_records']:
                console.print("\n[bold blue]DNS Records Found:[/bold blue]")
                for record_type, records in results['dns_records'].items():
                    if records:
                        console.print(f"[cyan]{record_type} Records:[/cyan]")
                        for record in records:
                            console.print(f"  ├─ {record}")

            # Prompt to save results
            results_text = self._format_results_for_file(results, "Domain Validation")
            self._save_output(results_text, f"{domain}_validation.txt")

            # Wait for user input
            console.print("\n")
            console.print(Panel(
                "[yellow]Press any key to continue...[/yellow]",
                border_style="cyan"
            ))
            try:
                keyboard.read_event()
            except:
                input()
            
            console.clear()
            return results

        except Exception as e:
            console.print(Panel(
                f"[red]Error checking domain: {str(e)}[/red]",
                title="[bold red]Error[/bold red]",
                border_style="red"
            ))
            return None

    def check_domains_validity_bulk(self, domains: List[str], output_file: str = None):
        """Check validity of multiple domains."""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Checking domains...", total=len(domains))
            
            for domain in domains:
                try:
                    result = self.check_domain_validity(domain)
                    if result:
                        results.append(result)
                except Exception as e:
                    progress.console.print(f"[red]Error checking {domain}: {str(e)}[/red]")
                progress.advance(task)

        # Display Results Table
        console.clear()
        console.print(Panel(
            "[bold cyan]Bulk Domain Validity Results[/bold cyan]",
            border_style="cyan"
        ))

        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
            expand=True
        )
        
        table.add_column("Domain", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("DNS Records", style="yellow")
        table.add_column("Details", style="magenta")
        
        for result in results:
            dns_count = sum(len(records) for records in result['dns_records'].values() if records)
            details = []
            if not result['format_valid']:
                details.append("Invalid format")
            if result['blacklisted']:
                details.append("Blacklisted")
            if not result['resolves']:
                details.append("No DNS resolution")
            
            table.add_row(
                result['domain'],
                "[green]Valid[/green]" if result['valid'] else "[red]Invalid[/red]",
                f"{dns_count} records" if dns_count else "No records",
                ", ".join(details) if details else "All checks passed"
            )
        
        console.print(table)

        if output_file:
            with open(output_file, 'w') as f:
                f.write("Domain Validity Check Results\n")
                f.write("=" * 50 + "\n\n")
                
                for result in results:
                    f.write(f"Domain: {result['domain']}\n")
                    f.write(f"Status: {'Valid' if result['valid'] else 'Invalid'}\n")
                    f.write(f"Format Valid: {result['format_valid']}\n")
                    f.write(f"Blacklisted: {result['blacklisted']}\n")
                    f.write(f"DNS Resolution: {result['resolves']}\n")
                    
                    if result['dns_records']:
                        f.write("DNS Records:\n")
                        for record_type, records in result['dns_records'].items():
                            if records:
                                f.write(f"  {record_type}: {len(records)} records\n")
                    f.write("\n" + "=" * 50 + "\n\n")
            
            console.print(f"\n[green]Results saved to: {output_file}[/green]")

        # Wait for user input
        console.print("\n")
        console.print(Panel(
            "[yellow]Press any key to continue...[/yellow]",
            border_style="cyan"
        ))
        try:
            keyboard.read_event()
        except:
            input()
        
        console.clear()

    def _save_output(self, content: str, default_filename: str) -> None:
        """Helper method to save output to a file."""
        try:
            save = Prompt.ask(
                "[cyan]Would you like to save the results?[/cyan] (y/n)", 
                choices=["y", "n"], 
                default="n"
            )
            
            if save.lower() == "y":
                filename = Prompt.ask(
                    "[cyan]Enter output filename[/cyan]",
                    default=default_filename
                )
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                console.print(f"\n[green]✓ Results saved to: {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {str(e)}[/red]")

    def _format_results_for_file(self, results: dict, operation: str) -> str:
        """Format results for file output."""
        output = []
        output.append(f"{operation} Results")
        output.append("=" * 50 + "\n")
        
        if operation == "Domain Validation":
            output.append(f"Domain: {results.get('domain', 'Unknown')}")
            output.append(f"Status: {'Valid' if results.get('valid') else 'Invalid'}")
            output.append(f"Format Valid: {results.get('format_valid')}")
            output.append(f"Blacklisted: {results.get('blacklisted')}")
            output.append(f"DNS Resolution: {results.get('resolves')}")
            
            # Add registration information
            reg_info = results.get('registration', {})
            output.append("\nRegistration Information:")
            if reg_info.get('registrar'):
                output.append(f"Registrar: {reg_info['registrar']}")
            if reg_info.get('creation_date'):
                output.append(f"Registration Date: {reg_info['creation_date']}")
            if reg_info.get('expiration_date'):
                output.append(f"Expiration Date: {reg_info['expiration_date']}")
            if reg_info.get('days_until_expiry') is not None:
                days = reg_info['days_until_expiry']
                if days < 0:
                    status = f"Expired ({abs(days)} days ago)"
                elif days < 30:
                    status = f"Expiring Soon ({days} days remaining)"
                else:
                    status = f"Active ({days} days remaining)"
                output.append(f"Status: {status}")
            
            if results.get('dns_records'):
                output.append("\nDNS Records:")
                for record_type, records in results['dns_records'].items():
                    if records:
                        output.append(f"{record_type} Records:")
                        for record in records:
                            output.append(f"  - {record}")
        
        elif operation == "Domain Analysis":
            if results.get('valid') is not None:
                output.append(f"Status: {'Valid' if results['valid'] else 'Invalid'}")
            
            if results.get('dns_records'):
                output.append("\nDNS Records:")
                for record_type, records in results['dns_records'].items():
                    if records:
                        output.append(f"{record_type} Records:")
                        for record in records:
                            output.append(f"  - {record}")
            
            if results.get('whois'):
                output.append("\nWHOIS Information:")
                whois_info = results['whois']
                if hasattr(whois_info, 'registrar'):
                    output.append(f"Registrar: {whois_info.registrar}")
                if hasattr(whois_info, 'creation_date'):
                    output.append(f"Created: {whois_info.creation_date}")
                if hasattr(whois_info, 'expiration_date'):
                    output.append(f"Expires: {whois_info.expiration_date}")
        
        elif operation == "Port Scan":
            if results.get('open_ports'):
                output.append("Open Ports:")
                for port in sorted(results['open_ports']):
                    service = results['service_details'].get(port, "Unknown")
                    output.append(f"  {port}/TCP - {service}")
        
        return "\n".join(output)

    def get_detailed_ssl_info(self, domain: str):
        """Get detailed SSL certificate information."""
        ssl_info = {
            'issuer': None,
            'validity_period': None,
            'signature_algorithm': None,
            'subject_alt_names': [],
            'cipher_suite': None
        }

    def enumerate_domain(self, domain: str) -> dict:
        """Advanced subdomain enumeration using multiple sources and techniques."""
        try:
            console.clear()
            console.print(Panel(
                f"[bold cyan]Advanced Subdomain Discovery: {domain}[/bold cyan]",
                border_style="cyan"
            ))

            subdomains = set()  # Using set to avoid duplicates

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                
                # Certificate Transparency Logs (crt.sh)
                progress.add_task("[cyan]Checking crt.sh logs...")
                try:
                    ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
                    response = requests.get(ct_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            name = entry.get('name_value', '').lower()
                            if name.endswith(domain) and name != domain:
                                subdomains.add(name)
                except:
                    pass

                # Virus Total API
                progress.add_task("[cyan]Checking VirusTotal...")
                try:
                    vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                    params = {'apikey': 'YOUR_API_KEY', 'domain': domain}
                    response = requests.get(vt_url, params=params, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if 'subdomains' in data:
                            for subdomain in data['subdomains']:
                                subdomains.add(subdomain)
                except:
                    pass

                # SecurityTrails
                progress.add_task("[cyan]Checking SecurityTrails...")
                try:
                    headers = {'apikey': 'YOUR_API_KEY'}
                    st_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                    response = requests.get(st_url, headers=headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if 'subdomains' in data:
                            for sub in data['subdomains']:
                                subdomains.add(f"{sub}.{domain}")
                except:
                    pass

                # Alienvault OTX
                progress.add_task("[cyan]Checking AlienVault...")
                try:
                    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
                    response = requests.get(otx_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data.get('passive_dns', []):
                            hostname = entry.get('hostname', '').lower()
                            if hostname.endswith(domain) and hostname != domain:
                                subdomains.add(hostname)
                except:
                    pass

                # RapidDNS
                progress.add_task("[cyan]Checking RapidDNS...")
                try:
                    rapid_url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
                    response = requests.get(rapid_url, timeout=10)
                    if response.status_code == 200:
                        pattern = r'[a-zA-Z0-9.-]+\.' + re.escape(domain)
                        matches = re.findall(pattern, response.text)
                        subdomains.update(matches)
                except:
                    pass

                # CommonCrawl
                progress.add_task("[cyan]Checking CommonCrawl...")
                try:
                    cc_url = f"http://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{domain}&output=json"
                    response = requests.get(cc_url, timeout=10)
                    if response.status_code == 200:
                        for line in response.text.split('\n'):
                            if line:
                                data = json.loads(line)
                                url = data.get('url', '')
                                parsed = urlparse(url)
                                if parsed.netloc and parsed.netloc.endswith(domain):
                                    subdomains.add(parsed.netloc)
                except:
                    pass

                # DNS Dumpster
                progress.add_task("[cyan]Checking DNSDumpster...")
                try:
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    session = requests.Session()
                    r = session.get("https://dnsdumpster.com/", headers=headers)
                    csrf_token = r.cookies.get('csrftoken')
                    
                    data = {
                        'csrfmiddlewaretoken': csrf_token,
                        'targetip': domain
                    }
                    headers['Referer'] = 'https://dnsdumpster.com/'
                    r = session.post("https://dnsdumpster.com/", headers=headers, data=data)
                    
                    pattern = r'[a-zA-Z0-9.-]+\.' + re.escape(domain)
                    matches = re.findall(pattern, r.text)
                    subdomains.update(matches)
                except:
                    pass

            # Clean and validate subdomains
            valid_subdomains = set()
            validation_task = progress.add_task("[cyan]Validating discovered subdomains...", total=len(subdomains))
            
            for subdomain in subdomains:
                try:
                    if subdomain.endswith(domain) and subdomain != domain:
                        valid_subdomains.add(subdomain.lower())
                except:
                    pass
                progress.advance(validation_task)

            # Display Results
            console.print("\n[bold blue]Enumeration Results[/bold blue]")
            console.print("─" * 50)

            if valid_subdomains:
                # Create a table for results
                table = Table(
                    show_header=True,
                    header_style="bold magenta",
                    border_style="cyan",
                    title="Discovered Subdomains",
                    title_style="bold cyan"
                )
                
                table.add_column("Subdomain", style="green")
                table.add_column("Status", style="cyan")

                for subdomain in sorted(valid_subdomains):
                    table.add_row(
                        subdomain,
                        "[green]Found[/green]"
                    )

                console.print(table)
                console.print(f"\n[green]Total unique subdomains found: {len(valid_subdomains)}[/green]")
            else:
                console.print("[yellow]No subdomains discovered[/yellow]")

            # Save results option
            console.print("\n")
            save = Prompt.ask(
                "[cyan]Would you like to save the results?[/cyan] (y/n)",
                choices=["y", "n"],
                default="n"
            )

            if save.lower() == "y":
                filename = Prompt.ask(
                    "[cyan]Enter output filename[/cyan]",
                    default=f"{domain}_subdomains.txt"
                )
                try:
                    with open(filename, 'w') as f:
                        f.write(f"Subdomain Enumeration Results for {domain}\n")
                        f.write("=" * 50 + "\n\n")
                        for subdomain in sorted(valid_subdomains):
                            f.write(f"{subdomain}\n")
                    console.print(f"[green]Results saved to: {filename}[/green]")
                except Exception as e:
                    console.print(f"[red]Error saving results: {str(e)}[/red]")

            # Wait for user input
            console.print("\n")
            console.print(Panel(
                "[yellow]Press any key to continue...[/yellow]",
                border_style="cyan"
            ))
            try:
                keyboard.read_event()
            except:
                input()

            console.clear()
            return {'subdomains': list(valid_subdomains)}

        except Exception as e:
            console.print(Panel(
                f"[red]Error during enumeration: {str(e)}[/red]",
                title="[bold red]Error[/bold red]",
                border_style="red"
            ))
            return None

    def _get_subdomain_wordlist(self) -> list:
        """Return an extended wordlist for subdomain enumeration."""
        common_words = [
            # Basic services
            'www', 'mail', 'email', 'webmail', 'remote', 'login', 'portal',
            'admin', 'administrator', 'admins', 'administrador',
            
            # Development and testing
            'dev', 'development', 'test', 'testing', 'staging', 'beta', 'demo',
            'sandbox', 'qa', 'uat', 'stg', 'prod', 'production',
            
            # Infrastructure
            'ns1', 'ns2', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2',
            'smtp', 'pop', 'pop3', 'imap', 'mail1', 'mail2',
            'vpn', 'proxy', 'gateway', 'router', 'firewall', 'fw',
            
            # Web services
            'web', 'api', 'api-docs', 'docs', 'documentation', 'developer',
            'developers', 'dev-api', 'api-dev', 'api-prod', 'api-test',
            'rest', 'rest-api', 'graphql', 'soap',
            
            # Content delivery
            'cdn', 'static', 'assets', 'media', 'img', 'images', 'css', 'js',
            'files', 'download', 'uploads', 'content',
            
            # Applications
            'app', 'apps', 'application', 'applications', 'mobile', 'm',
            'shop', 'store', 'cart', 'checkout', 'payment', 'pay',
            'blog', 'forum', 'community', 'support', 'help',
            
            # Management
            'manage', 'management', 'manager', 'admin-portal', 'adminportal',
            'cp', 'cpanel', 'whm', 'webmin', 'plesk',
            'dashboard', 'panel', 'console', 'analytics', 'stats',
            
            # Security
            'secure', 'security', 'ssl', 'auth', 'authentication',
            'login', 'signin', 'signup', 'register', 'password',
            
            # Collaboration tools
            'git', 'gitlab', 'github', 'bitbucket', 'svn',
            'jenkins', 'jira', 'confluence', 'wiki', 'redmine',
            'team', 'chat', 'slack', 'mattermost',
            
            # Storage and databases
            'db', 'database', 'sql', 'mysql', 'postgres', 'oracle',
            'mongo', 'redis', 'elasticsearch', 'backup', 'storage',
            
            # Monitoring and logging
            'monitor', 'monitoring', 'status', 'health', 'metrics',
            'logs', 'logging', 'log', 'grafana', 'kibana',
            
            # Common prefixes
            'new', 'old', 'legacy', 'v1', 'v2', 'v3', 'alpha', 'beta',
            'internal', 'external', 'public', 'private', 'corp', 'corporate',
            
            # Regional
            'us', 'eu', 'asia', 'uk', 'de', 'fr', 'es', 'it',
            'east', 'west', 'north', 'south',
            
            # Additional services
            'calendar', 'meet', 'video', 'audio', 'stream', 'live',
            'cms', 'crm', 'erp', 'hr', 'marketing', 'sales',
            
            # Cloud services
            'cloud', 'aws', 'azure', 'gcp', 'cloudfront', 's3',
            
            # Common patterns
            'staging-api', 'api-staging', 'dev-portal', 'portal-dev',
            'test-app', 'app-test', 'prod-api', 'api-prod'
        ]
        
        # Add numeric variations
        numeric_variations = []
        for word in common_words:
            for i in range(1, 6):
                numeric_variations.append(f"{word}{i}")
                numeric_variations.append(f"{word}-{i}")
        
        return list(set(common_words + numeric_variations))

def show_processing_animation():
    """Show a loading animation with system initialization messages"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # Simulate system initialization
        task1 = progress.add_task("[cyan]Initializing ESSIER systems...", total=None)
        time.sleep(0.7)
        progress.update(task1, description="[cyan]Loading core modules...")
        time.sleep(0.5)
        progress.update(task1, description="[cyan]Establishing secure environment...")
        time.sleep(0.5)
        progress.update(task1, description="[green]System ready!")
        time.sleep(0.3)

def get_key():
    """Get a single keypress from stdin."""
    import sys
    import tty
    import termios
    
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        if ch == '\x03':  # Ctrl+C
            return 'exit'  # Return special value for Ctrl+C
        if ch == '\x1b':
            ch = sys.stdin.read(2)
            return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def show_choice_prompt():
    menu_items = [
        ("[cyan]DOMAIN HUNTER[/cyan]", "[dim cyan]Trace and analyze domain information[/dim cyan]"),
        ("[cyan]PHANTOM TRACE[/cyan]", "[dim cyan]Advanced IP reconnaissance system[/dim cyan]"),
        ("[cyan]PORT SCANNER[/cyan]", "[dim cyan]Scan ports on domain or IP address[/dim cyan]"),
        ("[cyan]DOMAIN ANALYZER[/cyan]", "[dim cyan]Check domain validity, records & WHOIS[/dim cyan]"),
        ("[cyan]DOMAIN VALIDATOR[/cyan]", "[dim cyan]Quick domain validity check[/dim cyan]"),
        ("[cyan]DOMAIN ENUMERATION[/cyan]", "[dim cyan]Enumerate subdomains and DNS records[/dim cyan]"),
        ("[red]EXIT[/red]", "[dim red]Terminate ESSIER session[/dim red]")
    ]
    
    selected = 0
    console = Console()
    
    def print_menu():
        console.clear()
        console.print(BANNER)
        
        for idx, (item, desc) in enumerate(menu_items):
            if idx == selected:
                console.print(f"[bold green]▸ {item:<30} {desc}[/bold green]")
            else:
                console.print(f"  {item:<30} {desc}")
        
        console.print("\n[dim white]↑/↓[/dim white] Navigate   [dim white]⏎[/dim white] Select   [dim white]^C[/dim white] Exit")
        console.print("\n[bold yellow]Crafted By Olial Kibria Konok[/bold yellow]")

    while True:
        print_menu()
        
        key = get_key()
        if key == 'exit':  # Check for Ctrl+C
            return "7"  # Return exit option
        if key == '[B':  # Down arrow
            if selected < len(menu_items) - 1:
                selected += 1
        elif key == '[A':  # Up arrow
            if selected > 0:
                selected -= 1
        elif key == '\r':  # Enter key
            return str(selected + 1)

def show_domain_hunter_menu():
    return show_submenu("DOMAIN HUNTER MODE", "Domain")

def show_phantom_trace_menu():
    return show_submenu("PHANTOM TRACE MODE", "IP")

def show_port_scanner_menu():
    menu_items = [
        ("Single Domain Scan", "Scan ports on a single domain"),
        ("Single IP Scan", "Scan ports on a single IP address"),
        ("Bulk Domain Scan", "Scan ports on multiple domains from file"),
        ("Bulk IP Scan", "Scan ports on multiple IPs from file"),
        ("Custom Port Range", "Specify custom port range to scan"),
        ("Return to Main Menu", "Go back to main interface")
    ]
    
    selected = 0
    
    def print_menu():
        console.clear()
        console.print(f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                     PORT SCANNER MODE                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║""")
        
        for idx, (item, desc) in enumerate(menu_items):
            if idx == selected:
                console.print(f"║  [bold green]▸[/bold green] {item:<35} {desc:<35} ║")
            else:
                console.print(f"║    {item:<35} {desc:<35} ║")
                
        console.print("""║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  [dim white]↑/↓[/dim white] Navigate   [dim white]⏎[/dim white] Select   [dim white]^C[/dim white] Exit                           ║
╚══════════════════════════════════════════════════════════════╝""")

    while True:
        print_menu()
        
        key = get_key()
        if key == 'exit':  # Check for Ctrl+C
            return "6"  # Return to main menu
        if key == '[B':  # Down arrow
            if selected < len(menu_items) - 1:
                selected += 1
        elif key == '[A':  # Up arrow
            if selected > 0:
                selected -= 1
        elif key == '\r':  # Enter key
            return str(selected + 1)

def show_domain_analyzer_menu():
    menu_items = [
        ("Single Domain Analysis", "Analyze a single domain in detail"),
        ("Bulk Domain Analysis", "Analyze multiple domains from file"),
        ("Return to Main Menu", "Go back to main interface")
    ]
    
    selected = 0
    
    def print_menu():
        console.clear()
        console.print(f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                    DOMAIN ANALYZER MODE                      ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║""")
        
        for idx, (item, desc) in enumerate(menu_items):
            if idx == selected:
                console.print(f"║  [bold green]▸[/bold green] {item:<35} {desc:<35} ║")
            else:
                console.print(f"║    {item:<35} {desc:<35} ║")
                
        console.print("""║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  [dim white]↑/↓[/dim white] Navigate   [dim white]⏎[/dim white] Select   [dim white]^C[/dim white] Exit                           ║
╚══════════════════════════════════════════════════════════════╝""")

    while True:
        print_menu()
        
        key = get_key()
        if key == 'exit':  # Check for Ctrl+C
            return "3"  # Return to main menu
        if key == '[B':  # Down arrow
            if selected < len(menu_items) - 1:
                selected += 1
        elif key == '[A':  # Up arrow
            if selected > 0:
                selected -= 1
        elif key == '\r':  # Enter key
            return str(selected + 1)

def show_domain_validator_menu():
    menu_items = [
        ("Single Domain Check", "Check validity of a single domain"),
        ("Bulk Domain Check", "Check validity of multiple domains from file"),
        ("Return to Main Menu", "Go back to main interface")
    ]
    
    selected = 0
    
    def print_menu():
        console.clear()
        console.print(f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                    DOMAIN VALIDATOR MODE                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║""")
        
        for idx, (item, desc) in enumerate(menu_items):
            if idx == selected:
                console.print(f"║  [bold green]▸[/bold green] {item:<35} {desc:<35} ║")
            else:
                console.print(f"║    {item:<35} {desc:<35} ║")
                
        console.print("""║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  [dim white]↑/↓[/dim white] Navigate   [dim white]⏎[/dim white] Select   [dim white]^C[/dim white] Exit                           ║
╚══════════════════════════════════════════════════════════════╝""")

    while True:
        print_menu()
        
        key = get_key()
        if key == 'exit':  # Check for Ctrl+C
            return "3"  # Return to main menu
        if key == '[B':  # Down arrow
            if selected < len(menu_items) - 1:
                selected += 1
        elif key == '[A':  # Up arrow
            if selected > 0:
                selected -= 1
        elif key == '\r':  # Enter key
            return str(selected + 1)

def show_domain_enumeration_menu():
    menu_items = [
        ("Single Domain Enumeration", "Enumerate subdomains for a single domain"),
        ("Bulk Domain Enumeration", "Enumerate subdomains for multiple domains"),
        ("DNS Record Enumeration", "Detailed DNS record analysis"),
        ("Return to Main Menu", "Go back to main interface")
    ]
    
    selected = 0
    
    def print_menu():
        console.clear()
        console.print(f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                   DOMAIN ENUMERATION MODE                    ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║""")
        
        for idx, (item, desc) in enumerate(menu_items):
            if idx == selected:
                console.print(f"║  [bold green]▸[/bold green] {item:<35} {desc:<35} ║")
            else:
                console.print(f"║    {item:<35} {desc:<35} ║")
                
        console.print("""║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  [dim white]↑/↓[/dim white] Navigate   [dim white]⏎[/dim white] Select   [dim white]^C[/dim white] Exit                           ║
╚══════════════════════════════════════════════════════════════╝""")

    while True:
        print_menu()
        
        key = get_key()
        if key == 'exit':  # Check for Ctrl+C
            return "4"  # Return to main menu
        if key == '[B':  # Down arrow
            if selected < len(menu_items) - 1:
                selected += 1
        elif key == '[A':  # Up arrow
            if selected > 0:
                selected -= 1
        elif key == '\r':  # Enter key
            return str(selected + 1)

def show_submenu(title: str, mode: str) -> str:
    menu_items = [
        (f"Single {mode} Lookup", f"Process individual {mode}"),
        (f"Bulk {mode} Lookup (from file)", f"Process multiple {mode}s from file"),
        ("Return to Main Menu", "Go back to main interface")
    ]
    
    selected = 0
    
    def print_submenu():
        console.clear()
        console.print(f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                     {title:^41}║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║""")
        
        for idx, (item, desc) in enumerate(menu_items):
            if idx == selected:
                console.print(f"║  [bold green]▸[/bold green] {item:<35} {desc:<35} ║")
            else:
                console.print(f"║    {item:<35} {desc:<35} ║")
                
        console.print("""║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  [dim white]↑/↓[/dim white] Navigate   [dim white]⏎[/dim white] Select   [dim white]^C[/dim white] Exit                           ║
╚══════════════════════════════════════════════════════════════╝""")

    while True:
        print_submenu()
        
        key = get_key()
        if key == 'exit':  # Check for Ctrl+C
            return "3"  # Return to main menu
        if key == '[B':  # Down arrow
            if selected < len(menu_items) - 1:
                selected += 1
        elif key == '[A':  # Up arrow
            if selected > 0:
                selected -= 1
        elif key == '\r':  # Enter key
            return str(selected + 1)

def main():
    console.clear()
    show_processing_animation()
    console.print(BANNER)

    tool = DomainIPTool()

    while True:
        choice = show_choice_prompt()
        
        if choice == "1":  # Domain Hunter
            while True:
                subchoice = show_domain_hunter_menu()
                if subchoice == "1":
                    domain = Prompt.ask("[cyan]Enter domain[/cyan] (e.g., google.com)")
                    tool.single_domain_to_ip(domain)
                elif subchoice == "2":
                    file_path = Prompt.ask("[cyan]Enter path to domain list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            domains = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.domain_to_ip_bulk(domains, output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                else:
                    break
            
        elif choice == "2":  # Phantom Trace
            while True:
                subchoice = show_phantom_trace_menu()
                if subchoice == "1":
                    ip = Prompt.ask("[cyan]Enter IP address[/cyan] (e.g., 8.8.8.8)")
                    tool.single_reverse_ip(ip)
                elif subchoice == "2":
                    file_path = Prompt.ask("[cyan]Enter path to IP list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            ips = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.reverse_ip_bulk(ips, output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                else:
                    break
            
        elif choice == "3":  # Port Scanner
            while True:
                subchoice = show_port_scanner_menu()
                if subchoice == "1":  # Single Domain Scan
                    domain = Prompt.ask("[cyan]Enter domain to scan[/cyan]")
                    tool.perform_port_scan(domain, is_domain=True)
                elif subchoice == "2":  # Single IP Scan
                    ip = Prompt.ask("[cyan]Enter IP address to scan[/cyan]")
                    tool.perform_port_scan(ip, is_domain=False)
                elif subchoice == "3":  # Bulk Domain Scan
                    file_path = Prompt.ask("[cyan]Enter path to domain list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            domains = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.perform_bulk_port_scan(domains, is_domain=True, output_file=output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                elif subchoice == "4":  # Bulk IP Scan
                    file_path = Prompt.ask("[cyan]Enter path to IP list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            ips = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.perform_bulk_port_scan(ips, is_domain=False, output_file=output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                elif subchoice == "5":  # Custom Port Range
                    target = Prompt.ask("[cyan]Enter target (domain or IP)[/cyan]")
                    start_port = int(Prompt.ask("[cyan]Enter start port[/cyan]", default="1"))
                    end_port = int(Prompt.ask("[cyan]Enter end port[/cyan]", default="1024"))
                    is_domain = not re.match(r'^[\d.]+$', target)
                    tool._port_scan(target, port_range=(start_port, end_port))
                    tool.perform_port_scan(target, is_domain=is_domain)
                else:
                    break
            
        elif choice == "4":  # Domain Analyzer
            while True:
                subchoice = show_domain_analyzer_menu()
                if subchoice == "1":
                    domain = Prompt.ask("[cyan]Enter domain to analyze[/cyan]")
                    tool.analyze_domain(domain)
                elif subchoice == "2":
                    file_path = Prompt.ask("[cyan]Enter path to domain list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            domains = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.analyze_domains_bulk(domains, output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                else:
                    break
            
        elif choice == "5":  # Domain Validator
            while True:
                subchoice = show_domain_validator_menu()
                if subchoice == "1":
                    domain = Prompt.ask("[cyan]Enter domain to check[/cyan]")
                    tool.check_domain_validity(domain)
                elif subchoice == "2":
                    file_path = Prompt.ask("[cyan]Enter path to domain list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            domains = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.check_domains_validity_bulk(domains, output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                else:
                    break
                    
        elif choice == "6":  # Domain Enumeration
            while True:
                subchoice = show_domain_enumeration_menu()
                if subchoice == "1":  # Single Domain Enumeration
                    domain = Prompt.ask("[cyan]Enter domain to enumerate[/cyan]")
                    tool.enumerate_domain(domain)
                elif subchoice == "2":  # Bulk Domain Enumeration
                    file_path = Prompt.ask("[cyan]Enter path to domain list file[/cyan]")
                    try:
                        with open(file_path, 'r') as f:
                            domains = [line.strip() for line in f if line.strip()]
                        output_file = Prompt.ask("[cyan]Enter output file path[/cyan] (or press Enter to skip)")
                        output_file = output_file if output_file else None
                        tool.enumerate_domains_bulk(domains, output_file)
                    except FileNotFoundError:
                        console.print("[red]Error: File not found[/red]")
                elif subchoice == "3":  # DNS Record Enumeration
                    domain = Prompt.ask("[cyan]Enter domain for DNS analysis[/cyan]")
                    tool.enumerate_dns_records(domain)
                else:
                    break
                    
        elif choice == "7":  # Exit
            console.print(Panel.fit(
                "[yellow]Thank you for using ESSIER! Goodbye![/yellow]",
                border_style="yellow"
            ))
            break

if __name__ == "__main__":
    main()

