from django.http import JsonResponse
from apps.monitoring.utils import get_cached_avg_login_time

def avg_login_time_api(request):
    days = int(request.GET.get('days', 1))
    return JsonResponse(get_cached_avg_login_time(days))
