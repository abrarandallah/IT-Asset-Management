# add_fake_vulnerabilities.py
import os
import django
import random

# ✅ Configure Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'asset_manager.settings')  # Replace with your project name
django.setup()

from assets.models import RiskScanResult

# ✅ Vulnerability pools
small_cve_pool = [
    "CVE-2024-1001", "CVE-2023-2002", "CVE-2022-3003"
]

large_cve_pool = [
    "CVE-2023-1111", "CVE-2023-2222", "CVE-2023-3333",
    "CVE-2022-4444", "CVE-2021-5555", "CVE-2020-6666",
    "CVE-2019-7777", "CVE-2018-8888"
]

# ✅ Counter
updated_high, updated_medium = 0, 0

# ✅ Assign to HIGH risk assets
for result in RiskScanResult.objects.filter(risk_level='HIGH'):
    result.vulnerabilities = random.sample(large_cve_pool, random.randint(4, 6))
    result.save()
    updated_high += 1
    print(f"🔥 HIGH risk: {result.asset.name} → {len(result.vulnerabilities)} CVEs")

# ✅ Assign to MEDIUM risk assets
for result in RiskScanResult.objects.filter(risk_level='MEDIUM'):
    result.vulnerabilities = random.sample(small_cve_pool, random.randint(1, 2))
    result.save()
    updated_medium += 1
    print(f"⚠️ MEDIUM risk: {result.asset.name} → {len(result.vulnerabilities)} CVEs")

print(f"\n✅ Done! {updated_high} HIGH-risk and {updated_medium} MEDIUM-risk assets updated.")
