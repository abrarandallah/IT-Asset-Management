#C:\Users\HP\OneDrive\Documents\proj3\IT-Asset-Management\assets\admin.py
from django.contrib import admin
from .models import Asset
from django.contrib import admin
from .models import Asset, RiskScanResult, ScanLog, DetectedService

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'ip_address', 'asset_type', 'manufacturer', 'model',
        'mac_address', 'serial_number', 'location',
        'status', 'network_range', 'discovered_date',
        'warranty_expiration', 'purchase_date', 'replacement_due',
    )
    search_fields = ('name', 'ip_address', 'serial_number')
    list_filter = ('status', 'asset_type', 'network_range')


@admin.display(description='Vulnerability Count')
def vulnerability_count(self, obj):
    return len(obj.get_vulnerability_list())

@admin.register(RiskScanResult)
class RiskScanResultAdmin(admin.ModelAdmin):
    list_display = ['asset', 'risk_score', 'risk_level', 'scanned_at']
    readonly_fields = ['scanned_at']
    search_fields = ['asset__name']
    list_filter = ['risk_level']
    
    # Show vulnerabilities JSON in the admin panel
    fieldsets = (
        (None, {
            'fields': ('asset', 'risk_score', 'risk_level', 'vulnerabilities_json')
        }),
        ('Timestamps', {
            'fields': ('scanned_at',),
        }),
    )

admin.site.register(ScanLog)
admin.site.register(DetectedService)