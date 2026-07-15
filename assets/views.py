# C:\Users\HP\OneDrive\Documents\proj3\IT-Asset-Management\assets\views.py

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from .models import Asset, ScanLog, RiskScanResult
# CORRECTED IMPORT: Import NetworkScanner class and save_asset_data function
from .network_scanner import NetworkScanner, save_asset_data, scan_host_services 

from .risk_assessment import assess_all_assets 
from .reports import generate_asset_report
from datetime import date, datetime, timedelta # Import datetime and timedelta
from django.contrib.auth.decorators import login_required
from .forms import CustomUserCreationForm
from django.contrib.auth import login
from django.contrib.auth.views import LoginView
import threading
from django.utils.timesince import timesince
from django.db.models import Q # Import Q object for complex queries
from django.utils import timezone # Import timezone for timezone-aware datetimes


@login_required
def dashboard(request):
    selected_network = request.GET.get('network_range')
    if request.user.is_staff:
        networks = Asset.objects.values_list('network_range', flat=True).distinct()
    else:
        networks = []    
    
    all_available_networks = NetworkScanner.get_available_networks()
    current_subnet = all_available_networks[0] if all_available_networks else ''


    if selected_network:
        assets = Asset.objects.filter(network_range=selected_network)
    else:
        assets = Asset.objects.all()

    asset_types = {}
    for asset in assets:
        asset_types[asset.asset_type] = asset_types.get(asset.asset_type, 0) + 1

    return render(request, 'assets/dashboard.html', {
        'assets': assets,
        'asset_types': asset_types,
        'asset_count': assets.count(),
        'networks': networks,
        'selected_network': selected_network,
        'current_subnet': current_subnet, # Pass the adjusted subnet
        
    })


# Modified start_background_risk_assessment to accept arguments
def start_background_risk_assessment(assets_queryset=None, force_rescan=False):
    """
    Starts the vulnerability assessment in a background thread.
    Can be configured to scan specific assets or use default logic.
    """
    def run():
        # Call the assess_all_assets function with the passed queryset and flags
        assess_all_assets(assets_to_scan_queryset=assets_queryset, force_rescan=force_rescan)
    threading.Thread(target=run).start()


@login_required
def run_risk_scan(request):
    if request.method == 'POST':
        # Get optional parameters from the form (these values will come from your HTML form)
        scan_option = request.POST.get('scan_option', 'new_only') # Default to new_only if not provided
        
        assets_to_scan = None
        force_rescan_flag = False # Default to not forcing a full rescan
        message_text = "Background risk scan started."

        if scan_option == 'full_rescan':
            assets_to_scan = Asset.objects.all() # QuerySet for all assets
            force_rescan_flag = True # Set flag to force a full re-scan
            message_text = "✅ Background risk scan started (full re-scan). Please refresh later."
        elif scan_option == 'new_only':
            # Assets that have no risk scan results OR whose last scan is older than 7 days
            seven_days_ago = timezone.now() - timedelta(days=7) # Use timezone.now()

            # Using Q objects to combine conditions for filtering
            assets_to_scan = Asset.objects.filter(
                Q(riskscanresult__isnull=True) | # Asset has no associated RiskScanResult
                Q(riskscanresult__scanned_at__lt=seven_days_ago) # Or the existing scan result is old
            ).distinct() # Use distinct to avoid duplicates if an asset matches both conditions
            
            if not assets_to_scan.exists():
                messages.info(request, "No new or outdated assets found to scan.")
                return redirect('risk_dashboard')
            
            message_text = "✅ Background risk scan started for new/outdated assets. Please refresh later."
        else: # Fallback, e.g., if an unexpected value for scan_option is received
            messages.error(request, "Invalid scan option selected.")
            return redirect('risk_dashboard')


        # Start the background thread with the determined assets_to_scan and force_rescan flag
        start_background_risk_assessment(assets_queryset=assets_to_scan, force_rescan=force_rescan_flag)
        
        messages.success(request, message_text)
    return redirect('risk_dashboard')


@login_required
def run_scan(request):
    if request.method == 'POST':
        network_range = request.POST.get('network_range', '').strip()
        scan_type = request.POST.get('scan_type', 'quick')
        
        try:
            discovered_assets_for_saving = [] # Initialize a list to hold all discovered assets
            saved_count = 0 # Initialize a counter for saved assets

            if scan_type == 'multi':
                # Multiple networks from textarea
                networks = [n.strip() for n in network_range.split('\n') if n.strip()]
                if not networks:
                    messages.error(request, 'Please provide at least one network range')
                    return redirect('/')
                
                # CORRECTED CALL: Use NetworkScanner.parallel_network_scan()
                discovered_assets_for_saving = NetworkScanner.parallel_network_scan(networks)

                current_scanlog = ScanLog.objects.create(
                    network_range="multiple networks",
                    found_devices=len(discovered_assets_for_saving)
                )

                saved_count = save_asset_data(discovered_assets_for_saving, current_scanlog)

                messages.success(request, f'Multi-network scan completed! Found and saved {saved_count} devices across {len(networks)} networks.')
            
            else:
                # Single network (quick scan)
                if not network_range:
                    # CORRECTED CALL: Use NetworkScanner.get_available_networks() if auto-detect
                    all_available_networks = NetworkScanner.get_available_networks()
                    network_range = all_available_networks[0] if all_available_networks else "192.168.1.0/24" # Provide a default fallback


                # CORRECTED CALL: Use NetworkScanner.scan_network()
                discovered_assets_for_saving = NetworkScanner.scan_network(network_range)

                current_scanlog = ScanLog.objects.create(
                    network_range=network_range,
                    found_devices=len(discovered_assets_for_saving)
                )

                saved_count = save_asset_data(discovered_assets_for_saving, current_scanlog)

                network_display = network_range or "auto-detected network"
                messages.success(request, f'Network scan completed on {network_display}! Found and saved {saved_count} devices.')
            

        except Exception as e:
            messages.error(request, f'Scan failed: {str(e)}')
    
    return redirect('/')

@login_required
def network_management(request):
    """New view for managing multiple networks"""
    networks = Asset.objects.values_list('network_range', flat=True).distinct()
    network_stats = []
    
    for network in networks:
        if network:
            asset_count = Asset.objects.filter(network_range=network).count()
            latest_scan = ScanLog.objects.filter(network_range=network).order_by('-timestamp').first()
            network_stats.append({
                'network': network,
                'asset_count': asset_count,
                'last_scan': latest_scan.timestamp if latest_scan else None
            })
    
    return render(request, 'assets/network_management.html', {
        'network_stats': network_stats,
        'total_networks': len(networks)
    })

@login_required
def risk_dashboard(request):
    # Load all existing risk results
    scan_results = RiskScanResult.objects.select_related('asset').all()

    if not scan_results:
        messages.info(request, "No risk results yet. Run a scan or refresh later.")
    
    # Count risk levels
    risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for r in scan_results:
        risk_counts[r.risk_level] += 1

    # Get the latest scan time (added part)
    latest_scan = RiskScanResult.objects.order_by('-scanned_at').first()
    last_scan_time = timesince(latest_scan.scanned_at) if latest_scan else None


    # Render with context
    return render(request, 'assets/risk_dashboard.html', {
        'risk_results': scan_results,
        'risk_counts': risk_counts,
        'high_risk_assets': [r for r in scan_results if r.risk_level == 'HIGH'],
        'last_scan_time': last_scan_time    # pass to template
    })


@login_required
def risk_dashboard_data(request):
    """
    JSON endpoint used by risk_dashboard.html to poll for live updates
    while a background risk scan is running, without needing a full
    page reload.
    """
    scan_results = RiskScanResult.objects.select_related('asset').all()

    risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for r in scan_results:
        risk_counts[r.risk_level] += 1

    latest_scan = RiskScanResult.objects.order_by('-scanned_at').first()
    last_scan_time = timesince(latest_scan.scanned_at) if latest_scan else None

    results_data = []
    for r in scan_results:
        asset_type = getattr(r.asset, 'asset_type', None) or 'Asset'
        model = getattr(r.asset, 'model', None) or 'Generic'
        location = getattr(r.asset, 'location', None) or 'Unassigned'
        masked = f"{asset_type}-{model}-{location}-{r.asset_id}"

        results_data.append({
            'masked_name': masked,
            'asset_type': (r.asset.asset_type or '').title(),
            'asset_type_icon': (r.asset.asset_type or '').lower(),
            'risk_score': r.risk_score,
            'risk_level': r.risk_level,
            'vulnerabilities': r.vulnerabilities or [],
            'scan_log_time': r.asset.scan_log.timestamp.strftime('%b %d, %Y %H:%M') if r.asset.scan_log else None,
            'scan_log_range': r.asset.scan_log.network_range if r.asset.scan_log else None,
        })

    return JsonResponse({
        'risk_counts': risk_counts,
        'last_scan_time': last_scan_time,
        'results': results_data,
        'is_staff': request.user.is_staff,
    })

@login_required
def reports(request):
    report_data = generate_asset_report()
    return render(request, 'assets/reports.html', report_data)

@login_required
def lifecycle_dashboard(request):
    today = date.today()
    one_year_from_now = today.replace(year=today.year + 1)

    # Use plural variable names to match context keys
    expiring_warranties = Asset.objects.filter(
        warranty_expiration__isnull=False,
        warranty_expiration__lte=one_year_from_now
    )

    overdue_replacements = Asset.objects.filter(
        replacement_due__isnull=False,
        replacement_due__lte=today
    )

    # Get all assets with risk scores
    risk_results = RiskScanResult.objects.select_related('asset__scan_log')

    # Build a list of assets with risk + lifecycle data
    assets_with_risk = []
    for result in risk_results:
        asset = result.asset
        asset.risk_score = result.risk_score  # Keep original scale (remove /10 if scores are already 0-10)
        asset.risk_level = result.risk_level
        assets_with_risk.append(asset)

    context = {
        'expiring_warranties': expiring_warranties,
        'overdue_replacements': overdue_replacements,
        'assets_with_risk': assets_with_risk,
    }
    return render(request, 'assets/lifecycle.html', context)

def scan_history(request):
    logs = ScanLog.objects.order_by('-timestamp')
    return render(request, 'assets/scan_history.html', {'logs': logs})


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)    # 🔐 Auto-login
            messages.success(request, "✅ Account created and you're now logged in!")
            return redirect('risk_dashboard')
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})


class CustomLoginView(LoginView):
    """
    Custom login view that supports a 'remember me' option.
    If 'remember me' is checked, the session persists for 2 weeks; otherwise, it expires on browser close.
    """
    template_name = 'login.html'

    def form_valid(self, form):
        remember_me = self.request.POST.get('remember_me', '').strip().lower()

        if remember_me != 'on':
            self.request.session.set_expiry(0)    # Session expires when browser closes (Django default behavior)
        else:
            self.request.session.set_expiry(1209600)    # 2 weeks

        return super().form_valid(form)