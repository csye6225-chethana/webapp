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
import logging
from django.conf import settings

from .models import User
from .models import Image

from backend_api.metrics import track_api_metrics, DatabaseQueryTimer, S3OperationTimer

logger = logging.getLogger(__name__)

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
    logger.debug("create_user This is a debug message.")
    logger.info("create_user This is an info message.")
    logger.warning("create_user This is a warning message.")
    logger.error("create_user This is an error message.")
    logger.critical("create_user This is a critical message.")
    try:
        connection.ensure_connection()
    except Exception:
        return HttpResponse(status=503)
    
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
    try:
        connection.ensure_connection()
    except Exception:
        return HttpResponse(status=503)
    
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
        if(field=='password' and len(value)<8):
            return Response({'error': 'Password should be atleast 8 charecters'}, status=status.HTTP_400_BAD_REQUEST)

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
    
# start image apis code

from django.http import HttpResponse, JsonResponse
import bcrypt
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

s3_client = boto3.client('s3') # initialize S3 client
# bucket_name = "myawsbucketbenny"  # Replace with your bucket name
bucket_name = settings.S3_BUCKET_NAME

def authenticate_user(request):
    try:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) != 2 or auth[0].lower() != "basic":
            return Response({'error': 'Invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)
        
        email, password = base64.b64decode(auth[1]).decode().split(':')
        user = User.objects.get(email=email)
        if check_password(password, user.password):
            return user, None
        else:
            return None, "Invalid credentials"
    except (User.DoesNotExist, ValueError):
        return None, "User not found or error in credentials format"


@api_view(['POST', 'GET', 'DELETE'])
@track_api_metrics
def image_view(request):
    logger.debug("image_view This is a debug message.")
    logger.info("image_view This is an info message.")
    logger.warning("image_view This is a warning message.")
    logger.error("image_view This is an error message.")
    logger.critical("image_view This is a critical message.")
    # Ensure database connection
    try:
        connection.ensure_connection()
    except Exception as e:
        logger.error("Database connection error: %s", str(e))
        return HttpResponse(status=503)

    # Authenticate user
    user, auth_error = authenticate_user(request)
    if auth_error:
        logger.warning("Authentication failed: %s", auth_error)
        return JsonResponse({"error": auth_error}, status=status.HTTP_401_UNAUTHORIZED)

    # Handle POST - Upload a new image
    if request.method == 'POST':
        if 'file' not in request.FILES:
            return JsonResponse({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        if Image.objects.filter(user_id=user).exists():
            return JsonResponse({"error": "User already has an uploaded image"}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        s3_key = f"{user.id}/{file_name}"

        # Define acceptable MIME types for images
        ACCEPTABLE_IMAGE_TYPES = ["image/png", "image/jpeg", "image/jpg"]
        file_type = uploaded_file.content_type
        if file_type not in ACCEPTABLE_IMAGE_TYPES:
            logger.error("Invalid file type. Only PNG, JPG, and JPEG are allowed.")
            return JsonResponse({"error": "Invalid file type. Only PNG, JPG, and JPEG are allowed."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with S3OperationTimer('upload_fileobj'):
                s3_client.upload_fileobj(uploaded_file, bucket_name, s3_key)
            url = f"s3://{bucket_name}/{s3_key}"

            with DatabaseQueryTimer('create_image'):
                image = Image.objects.create(
                    file_name=file_name,
                    url=url,
                    user_id=user
                )
            return JsonResponse({
                "id": str(image.id),
                "file_name": image.file_name,
                "url": image.url,
                "upload_date": image.upload_date.strftime("%Y-%m-%d"),
                "user_id": str(user.id)
            }, status=status.HTTP_201_CREATED)

        except (NoCredentialsError, ClientError) as e:
            logger.error("S3 upload failed: %s", str(e))
            return JsonResponse({"error": "S3 upload failed"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error("Unexpected error during upload: %s", str(e))
            return JsonResponse({"error": "Failed to upload image"}, status=status.HTTP_400_BAD_REQUEST)

    # Handle GET - Retrieve an image
    elif request.method == 'GET':
        try:
            image = Image.objects.get(user_id=user)
            return JsonResponse({
                "file_name": image.file_name,
                "id": image.id,
                "url": image.url,
                "uploaded_date": image.upload_date.strftime("%Y-%m-%d"),
                "user_id": str(image.user_id.id)
            }, status=status.HTTP_200_OK)
        except Image.DoesNotExist:
            return JsonResponse({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)

    # Handle DELETE - Delete an image
    elif request.method == 'DELETE':
        try:
            image = Image.objects.get(user_id=user)
            s3_client.delete_object(Bucket=bucket_name, Key=image.url.split(f"{bucket_name}/")[-1])
            image.delete()
            return HttpResponse(status=status.HTTP_204_NO_CONTENT)

        except Image.DoesNotExist:
            return JsonResponse({"error": "No images found for this user"}, status=status.HTTP_404_NOT_FOUND)
        except NoCredentialsError:
            logger.error("S3 credentials not available")
            return JsonResponse({"error": "S3 credentials not available"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error("Unexpected error during deletion: %s", str(e))
            return JsonResponse({"error": "Failed to delete image"}, status=status.HTTP_400_BAD_REQUEST)

    return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)

