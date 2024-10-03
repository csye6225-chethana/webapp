from django.utils.deprecation import MiddlewareMixin

# adding no cache to all apis in this repo
class CacheControlMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        response['Cache-Control'] = 'no-cache'
        return response