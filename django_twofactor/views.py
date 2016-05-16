from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.cache import cache
from .util import key_to_seed, random_base36_with_checksum, list_codes

import math
import random


GRIDCARD_CACHE_KEY = getattr(
    settings, "TWOFACTOR_GRIDCARD_CACHE_KEY", "twofactor-gridcard-{0}")
GRIDCARD_CACHE_TIME = getattr(
    settings, "TWOFACTOR_GRIDCARD_CACHE_TIME", 24 * 60 * 60)


def valid_code(code):
    """ Checks that the integer is 6 digits long """
    return int(math.log10(int(code))+1)==6

def valid_list(codes):
    if(len(codes)==0):
        return False
    for code in codes:
        if(valid_code(code))==False:
            return False
    return True


@never_cache
@login_required
def generate_gridcard(request):

    codelist = []
    cache_key = GRIDCARD_CACHE_KEY.format(request.user.username)
    key = cache.get(cache_key)

    while valid_list(codelist)==False:
        # new key and codes if there is no key in the cache or list invalid and non-empty
        if not key or len(codelist)>0:
            key = random_base36_with_checksum()
            cache.set(cache_key, key, GRIDCARD_CACHE_TIME)
        raw_seed = key_to_seed(key)
        codes = list_codes(raw_seed)

        codelist=[]
        for code in codes: codelist.append(code)

    context = {
        "key": key,
        "codes": codelist,
    }
    return render(request, "twofactor/gridcard.html", context)
