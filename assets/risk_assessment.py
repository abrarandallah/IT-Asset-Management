# C:\Users\HP\OneDrive\Documents\proj3\IT-Asset-Management\assets\risk_assessment.py
from .network_scanner import scan_host_services # <-- ADD THIS LINE
from datetime import datetime, timedelta
import requests
import time
from django.db.models import Q
from django.utils import timezone
from .models import Asset, RiskScanResult

# This class is responsible for looking up CVEs from various sources.
# It supports online sources like NVD, CVE Details, and CIRCL, as well as offline data for common products.
# It provides methods to retrieve vulnerabilities for a given product and version.
class CVELookup:
    def __init__(self):
        self.sources = [
            {
                'name': 'NVD NIST',
                'url_template': 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage=50',
                'parser': self._parse_nvd_response
            },
            {
                'name': 'CVE Details API',
                'url_template': 'https://www.cvedetails.com/json-feed.php?vendor_id=0&product={product}&version={version}',
                'parser': self._parse_cvedetails_response
            },
            {
                'name': 'CIRCL (backup)',
                'url_template': 'https://cve.circl.lu/api/search/{product}/{version}',
                'parser': self._parse_circl_response
            }
        ]
        
        self.offline_vulns = {
            'mysql': {
                '8.0.42': ['CVE-2024-20963', 'CVE-2024-20964', 'CVE-2024-20965'],
                '8.0': ['CVE-2023-21980', 'CVE-2023-21982', 'CVE-2023-22005']
            },
            'microsoft': {
                'rpc': ['CVE-2023-21756', 'CVE-2023-23397'],
                'netbios': ['CVE-2023-28252', 'CVE-2023-21554'],
                'smb': ['CVE-2023-21808', 'CVE-2023-23397']
            },
            'apache': {
                '2.4': ['CVE-2023-25690', 'CVE-2023-27522']
            },
            'nginx': {
                '1.20': ['CVE-2021-23017']
            }
        }

    def get_vulnerabilities(self, product, version=""):
        print(f"🔍 Looking up CVEs for {product} {version}")
        for source in self.sources:
            try:
                vulnerabilities = self._try_source(source, product, version)
                if vulnerabilities:
                    print(f"✅ Found {len(vulnerabilities)} CVEs from {source['name']}")
                    return vulnerabilities
            except Exception as e:
                print(f"⚠️ {source['name']} failed: {e}")

        offline_cves = self._get_offline_vulnerabilities(product, version)
        if offline_cves:
            print(f"📚 Using offline CVE data: {len(offline_cves)} vulnerabilities")
            return offline_cves
            
        print(f"❌ No vulnerabilities found for {product} {version}")
        return []

    def _try_source(self, source, product, version):
        url = source['url_template'].format(product=product.lower(), version=version)
        response = requests.get(url, timeout=10, headers={'User-Agent': 'IT-Asset-Management-Tool/1.0'})
        if response.status_code == 200:
            return source['parser'](response.json(), product, version)
        elif response.status_code == 404:
            return []
        else:
            raise Exception(f"HTTP {response.status_code}")
    #this definition is used to parse the response from the NVD API
    #it extracts the CVE IDs from the JSON response
    def _parse_nvd_response(self, data, product, version):
        return [vuln.get('cve', {}).get('id', 'Unknown') for vuln in data.get('vulnerabilities', [])][:10]
    
    #this definition is used to parse the response from the CVE Details API
    #it extracts the CVE IDs from the JSON response
    def _parse_cvedetails_response(self, data, product, version):
        return [item.get('cve_id', 'Unknown') for item in data[:10]] if isinstance(data, list) else []

    #this definition is used to parse the response from the CIRCL API
    #it extracts the CVE IDs from the JSON response
    def _parse_circl_response(self, data, product, version):
        return [cve.get("id", "Unknown") for cve in data.get("results", [])]

    def _get_offline_vulnerabilities(self, product, version):
        product_lower = product.lower()
        if product_lower in self.offline_vulns:
            product_data = self.offline_vulns[product_lower]
            if version in product_data:
                return product_data[version]
            major = '.'.join(version.split('.')[:2])
            if major in product_data:
                return product_data[major]
            return next(iter(product_data.values()), [])
        if 'rpc' in product_lower:
            return self.offline_vulns.get('microsoft', {}).get('rpc', [])
        if 'netbios' in product_lower:
            return self.offline_vulns.get('microsoft', {}).get('netbios', [])
        if 'smb' in product_lower or 'microsoft-ds' in product_lower:
            return self.offline_vulns.get('microsoft', {}).get('smb', [])
        return []

# This class performs risk assessment for IT assets.
# It calculates risk scores based on asset properties, vulnerabilities, and manufacturer data.
class RiskAssessment: # This class definition must be before its usage in assess_all_assets
    def __init__(self):
        self.vulnerability_db = {
            'Dell': ['CVE-2023-1234', 'CVE-2023-5678'],
            'HP': ['CVE-2023-9012', 'CVE-2023-3456'],
            'Cisco': ['CVE-2023-7890', 'CVE-2023-2345'],
            'Lenovo': ['CVE-2023-6789']
        }
        self.cve_lookup = CVELookup()
    # This function calculates the risk score for an asset based on its properties and vulnerabilities.
    # It considers the age of the asset, manufacturer vulnerabilities, asset type, IP address presence
    def calculate_risk_score(self, asset, vulnerabilities=None):
        risk_score = 0
        age_days = (datetime.now().date() - asset.discovered_date.date()).days
        if age_days > 365:
            risk_score += 30
        elif age_days > 180:
            risk_score += 15
        if asset.manufacturer in self.vulnerability_db:
            vuln_count = len(self.vulnerability_db[asset.manufacturer])
            risk_score += vuln_count * 10
        if asset.asset_type in ['server', 'network']:
            risk_score += 20
        if asset.ip_address:
            risk_score += 15
        if vulnerabilities:
            risk_score += len(vulnerabilities) * 5
        return min(risk_score, 100)

    def get_risk_level(self, score):
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        return 'LOW'

    def get_vulnerabilities(self, asset):
        if not asset.ip_address:
            print(f"⚠️ No IP address for {asset.name}")
            return []
        services = scan_host_services(asset.ip_address, quick_mode=True)
        print(f"🔍 Services for {asset.ip_address}: {services}")
        if not services:
            print(f"⚠️ No services detected on {asset.ip_address}")
            return []
        all_vulns = []
        for service in services:
            product = service.get('product', '')
            version = service.get('version', '')
            clean_product = normalize_service(product)
            if not clean_product:
                continue
            vulns = self.cve_lookup.get_vulnerabilities(clean_product, version)
            all_vulns.extend(vulns)
            time.sleep(0.5)
        return list(set(all_vulns))

# This function normalizes the service name to a standard format.
# It handles common cases like Microsoft products, MySQL, and ignores irrelevant services.
def normalize_service(product):
    if not product:
        return None
    product = product.strip().lower()
    if "microsoft" in product:
        return "Microsoft"
    elif "mysql" in product:
        return "MySQL"
    elif "httpapi" in product:
        return "Microsoft HTTPAPI"
    elif "netbios" in product or "rpc" in product or "tcpwrapped" in product:
        return None
    return product.split()[0].capitalize()

# This function performs a risk assessment for assets.
# It can now accept a specific queryset of assets, or scan all unscanned/outdated ones.
# Keeping the original name 'assess_all_assets'
def assess_all_assets(assets_to_scan_queryset=None, force_rescan=False, scan_interval_days=7):
    """
    Performs risk assessment for a given queryset of assets, or all unscanned/outdated assets.

    Args:
        assets_to_scan_queryset (QuerySet, optional): A Django QuerySet of Asset objects to scan.
                                                      If None, it will query for unscanned/outdated assets.
        force_rescan (bool): If True, ignores scan_interval_days and rescans all in assets_to_scan_queryset.
        scan_interval_days (int): Assets older than this many days will be re-scanned if not force_rescan.
    """
    # Initialize RiskAssessment here, after the class is defined
    ra = RiskAssessment() 
    results = []

    # If no specific assets are provided, determine which ones need scanning
    if assets_to_scan_queryset is None:
        print("🔍 Determining assets that need vulnerability assessment...")
        # Get assets that have never been scanned
        unscanned_assets = Asset.objects.filter(riskscanresult__isnull=True) # Corrected filter: is_null=True

        # Get assets whose last scan result is older than `scan_interval_days`
        # We use Q objects to combine these criteria
        # Ensure timezone-aware comparison
        outdated_scan_threshold = timezone.now() - timedelta(days=scan_interval_days)
        outdated_assets = Asset.objects.filter(
            riskscanresult__scanned_at__lt=outdated_scan_threshold
        )

        # Combine unscanned and outdated assets, ensuring no duplicates
        assets_to_process = (unscanned_assets | outdated_assets).distinct()

        if not assets_to_process.exists():
            print("✅ No new or outdated assets found needing vulnerability assessment.")
            return [] # Return empty list if nothing to scan
    else:
        # If a queryset is provided (e.g., for a single asset scan)
        assets_to_process = assets_to_scan_queryset
        if force_rescan:
            print("⚠️ Force re-scan requested for provided assets.")
        else:
            print(f"🔍 Scanning {assets_to_process.count()} provided assets.")

    print(f"📊 Starting vulnerability assessment for {assets_to_process.count()} assets...")

    for asset in assets_to_process:
        print(f"\nScanning asset: {asset.name} ({asset.ip_address})")
        
        # Check if asset has a previous scan result
        existing_scan_result = RiskScanResult.objects.filter(asset=asset).first()

        # If we're not forcing a rescan and there's a recent enough scan result, skip
        if not force_rescan and existing_scan_result:
            # Ensure timezone-aware comparison
            if (timezone.now() - existing_scan_result.scanned_at).days < scan_interval_days:
                print(f"ℹ️ Skipping {asset.name}. Last scan was recent ({existing_scan_result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')}).")
                continue

        if asset.ip_address:
            # The get_vulnerabilities function already calls scan_host_services
            vulnerabilities = ra.get_vulnerabilities(asset)
        else:
            vulnerabilities = []
            print(f"⚠️ {asset.name} has no IP address. Cannot scan for vulnerabilities.")

        score = ra.calculate_risk_score(asset, vulnerabilities)
        level = ra.get_risk_level(score)

        # Update or create the RiskScanResult for this specific asset
        RiskScanResult.objects.update_or_create(
            asset=asset,
            defaults={
                'risk_score': score,
                'risk_level': level,
                'vulnerabilities': vulnerabilities # This property handles JSON serialization
            }
        )
        print(f"💾 Stored/Updated risk assessment for {asset.name}")
        results.append({
            'asset': asset,
            'risk_score': score,
            'risk_level': level,
            'vulnerabilities': vulnerabilities
        })
    
    if not assets_to_process.exists():
        print("✅ No assets were selected for vulnerability assessment.")
    else:
        print(f"✅ Vulnerability assessment completed for {len(results)} assets.")
    return results