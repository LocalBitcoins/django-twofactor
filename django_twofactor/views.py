from django.shortcuts import render
from django.views.decorators.cache import never_cache
from .util import key_to_seed, random_base36_with_checksum, list_codes


@never_cache
def generate_gridcard(request):
    key = random_base36_with_checksum()
    raw_seed = key_to_seed(key)
    codes = list_codes(raw_seed)

    context = {
        "key": key,
        "codes": codes,
    }
    return render(request, "twofactor/gridcard.html", context)
