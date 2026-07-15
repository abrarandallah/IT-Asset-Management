from django import template
import random

register = template.Library()

@register.filter
def masked_name(asset):
    import random
    asset_type = getattr(asset, 'asset_type', None) or 'Asset'
    model = getattr(asset, 'model', None) or 'Generic'
    location = getattr(asset, 'location', None) or 'Unassigned'
    code = str(random.randint(1000, 9999))  # Safe, no MAC/IP

    return f"{asset_type}-{model}-{location}-{code}"

