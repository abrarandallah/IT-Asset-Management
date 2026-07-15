import os
import django
from datetime import datetime, timedelta
import random
from faker import Faker
from django.utils.timezone import make_aware, now # Import now() for current time

# --- Django Setup ---
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'asset_manager.settings') # Replace 'asset_manager' with your project's main settings module name
django.setup()

# Import your Asset and ScanLog models from your 'assets' app
from assets.models import Asset, ScanLog # Adjust 'assets' if your app is named differently

# --- Configuration ---
NUM_FAKE_ASSETS = 10 # *** CHANGED TO 10 AS REQUESTED ***
NUM_FAKE_SCAN_LOGS = 5 # Number of distinct fake scan logs to create
fake = Faker('fr_FR') # Use French locale for Faker

# Define choices based on your Asset model (adjust if your choices differ)
ASSET_TYPES = ['server', 'workstation', 'laptop', 'network', 'printer', 'mobile', 'storage']
MANUFACTURERS = ['Dell', 'HP', 'Lenovo', 'Cisco', 'Ubiquiti', 'Canon', 'Epson', 'Samsung', 'Apple', 'Microsoft', 'IBM']
STATUS_CHOICES = ['active', 'inactive', 'maintenance', 'retired', 'faulty']

def generate_fake_assets_with_multiple_scan_logs(num_assets, num_scan_logs):
    """
    Generates fake Asset objects and distributes them among multiple fake ScanLog entries.
    """
    print(f"Generating {num_assets} fake assets and {num_scan_logs} fake scan logs...")

    pre_created_scan_logs = []
    for i in range(num_scan_logs):
        network_range_val = f"192.168.{random.randint(1, 254)}.{random.choice([0, 128])}/24"

        scan_log = ScanLog.objects.create(
            network_range=network_range_val,
            found_devices=0, # Will update this later
        )
        pre_created_scan_logs.append(scan_log)
        print(f"  Created ScanLog: ID {scan_log.id} for {scan_log.network_range} on {scan_log.timestamp.strftime('%Y-%m-%d %H:%M')}")

    if not pre_created_scan_logs:
        print("Error: No scan logs were created. Aborting asset generation.")
        return

    generated_count = 0
    assets_to_create = []
    
    scan_log_asset_counts = {sl.id: 0 for sl in pre_created_scan_logs}

    existing_manufacturers = list(Asset.objects.values_list('manufacturer', flat=True).distinct())
    if not existing_manufacturers:
        existing_manufacturers = ['Dell', 'HP', 'Cisco', 'Lenovo']

    existing_locations = list(Asset.objects.values_list('location', flat=True).distinct())
    if not existing_locations:
        existing_locations = ['Head Office', 'Branch A', 'Warehouse', 'Lab 1', 'Reception']

    for i in range(num_assets):
        chosen_scan_log = random.choice(pre_created_scan_logs)

        discovered_date_naive = fake.date_time_between(start_date='-3y', end_date='-6m', tzinfo=None)
        discovered_date = make_aware(discovered_date_naive)
        
        purchase_date = discovered_date.date() - timedelta(days=random.randint(30, 300))
        warranty_expiration = discovered_date.date() + timedelta(days=random.randint(365, 1095))
        replacement_due = warranty_expiration + timedelta(days=random.randint(365, 365 * 2))

        ip_address = f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        assets_to_create.append(Asset(
            name=f"Device-{fake.word().capitalize()}-{i+1}",
            ip_address=ip_address,
            asset_type=random.choice(ASSET_TYPES),
            manufacturer=random.choice(MANUFACTURERS),
            discovered_date=discovered_date,
            network_range=chosen_scan_log.network_range,
            mac_address=fake.mac_address(),
            model=fake.bothify(text='Model-??##'),
            serial_number=fake.uuid4().replace('-', '')[:15].upper(),
            location=random.choice(existing_locations),
            status=random.choice(STATUS_CHOICES),
            warranty_expiration=warranty_expiration,
            purchase_date=purchase_date,
            replacement_due=replacement_due,
            scan_log=chosen_scan_log,
        ))
        scan_log_asset_counts[chosen_scan_log.id] += 1
        generated_count += 1

    try:
        Asset.objects.bulk_create(assets_to_create)
        print(f"\nSuccessfully created {generated_count} fake assets.")
        
        for sl_id, count in scan_log_asset_counts.items():
            scan_log = ScanLog.objects.get(id=sl_id)
            scan_log.found_devices = count
            scan_log.save()
            print(f"Updated ScanLog ID {scan_log.id} with {scan_log.found_devices} devices.")

    except django.db.utils.IntegrityError as e:
        print(f"Error during bulk_create (likely duplicate IP/unique constraint): {e}")
        print("Consider clearing existing data or modifying IP generation.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    generate_fake_assets_with_multiple_scan_logs(NUM_FAKE_ASSETS, NUM_FAKE_SCAN_LOGS)