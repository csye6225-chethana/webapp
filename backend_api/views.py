from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.hashers import make_password, check_password
import base64

from .models import User


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

    return response

def custom_404_view(request, exception):
    return HttpResponse(status=404)


@api_view(['GET', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD', 'POST'])
def create_user(request):
    if request.method in ['GET', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD']:
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    if 'HTTP_AUTHORIZATION' in request.META:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    
    if request.GET or not request.body:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    
    required_fields = {'email', 'password', 'first_name', 'last_name'}
    received_fields = set(request.data.keys())

    # Check if all required fields are present
    if not required_fields.issubset(received_fields):
        return Response({'error': f'All fields {required_fields} are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if any extra fields are present
    if any(field not in required_fields for field in received_fields):
        return Response({'error': f'Only fields {required_fields} are allowed.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if all required fields have non-empty values
    for field in required_fields:
        value = request.data.get(field)
        if not value or value.strip() == '':
            return Response({'error': f'The field {field} cannot be empty.'}, status=status.HTTP_400_BAD_REQUEST)
        if(field=='password' and len(value)<8):
            return Response({'error': 'Password should be atleast 8 charecters'}, status=status.HTTP_400_BAD_REQUEST)
    
    email = request.data.get('email')
    password = request.data.get('password')
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')

    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'A user with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        hashed_password = make_password(password)

        user = User.objects.create(
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name
        )

        return Response({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'account_created': user.account_created,
            'account_updated': user.account_updated
        }, status=status.HTTP_201_CREATED)
    except Exception:
        return Response({'error': 'Error creating user. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD', 'POST'])
def user_detail(request):
    
    if request.method in ['OPTIONS', 'DELETE', 'PATCH', 'HEAD', 'POST']:
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    if 'HTTP_AUTHORIZATION' not in request.META:
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) != 2 or auth[0].lower() != "basic":
            return Response({'error': 'Invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)
        
        email, password = base64.b64decode(auth[1]).decode().split(':')
    except (IndexError, base64.binascii.Error, UnicodeDecodeError, ValueError):
        return Response({'error': 'Invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if not check_password(password, user.password):
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    
    if request.method == 'GET':
        return get_user_details(user, request)
    elif request.method == 'PUT':
        return update_user_details(user, request)


def get_user_details(user, request):
    # do not allow body or query params
    if request.GET or request.body:
        return Response(status=status.HTTP_400_BAD_REQUEST)           
    
    try:
        return Response({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'account_created': user.account_created,
            'account_updated': user.account_updated
        })
    except Exception as e:
        return Response({'error': 'Error retrieving user details'}, status=status.HTTP_400_BAD_REQUEST)

def update_user_details(user, request):
    # do not allow query params
    if request.GET:
        return Response(status=status.HTTP_400_BAD_REQUEST)    
    
    allowed_fields = ["first_name", "last_name", "password"]
    received_fields = set(request.data.keys())

    # Check if atleast one field given for updation
    if not received_fields:
        return Response({'error': 'At least one field must be provided for update'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if any extra fields are present
    if any(field not in allowed_fields for field in received_fields):
        return Response({'error': f'Only fields {allowed_fields} are allowed.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if all required fields have non-empty values
    for field in received_fields:
        value = request.data.get(field)
        if not value or value.strip() == '':
            return Response({'error': f'The field {field} cannot be empty.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        if 'first_name' in request.data:
            user.first_name = request.data['first_name']
        if 'last_name' in request.data:
            user.last_name = request.data['last_name']
        if 'password' in request.data:
            user.password = make_password(request.data['password'])

        user.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return Response({'error': 'Error updating user details'}, status=status.HTTP_400_BAD_REQUEST)
