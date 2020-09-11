from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.cache import cache
from django.utils.encoding import force_text

from .util import key_to_seed, random_base36_with_checksum, list_codes


GRIDCARD_CACHE_KEY = getattr(
    settings, "TWOFACTOR_GRIDCARD_CACHE_KEY", "twofactor-gridcard-{0}")
GRIDCARD_CACHE_TIME = getattr(
    settings, "TWOFACTOR_GRIDCARD_CACHE_TIME", 24 * 60 * 60)


@never_cache
@login_required
def generate_gridcard(request):
    cache_key = GRIDCARD_CACHE_KEY.format(request.user.username)

    key = cache.get(cache_key)
    if not key:
        key = random_base36_with_checksum()
        cache.set(cache_key, key, GRIDCARD_CACHE_TIME)
    key = force_text(key)
    raw_seed = key_to_seed(key)
    codes = list_codes(raw_seed)

    context = {
        "key": key,
        "codes": codes,
    }
    return render(request, "twofactor/gridcard.html", context)
