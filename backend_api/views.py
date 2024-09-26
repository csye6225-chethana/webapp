from django.http import HttpResponse, JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseNotFound


@csrf_exempt 
def health_check(request):

    if request.method != 'GET':
        response = HttpResponse(status=405) # Method Not Allowed
        return response
    
    if request.body or request.GET:
        response = HttpResponse(status=400) # Bad Request if there's a payload
        return response
    
    try:
        connection.ensure_connection() # check connection to db
        response = HttpResponse(status=200) # 200 OK if the connection is successful
    except Exception:
        response = HttpResponse(status=503) # Service Unavailable if there's a database error

    response['Cache-Control'] = 'no-cache' # Add 'no-cache' header

    return response

def custom_404_view(request, exception):
    return HttpResponse(status=404)
    # return HttpResponseNotFound()
