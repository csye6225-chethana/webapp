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

from .models import User, Image
from backend_api.metrics import track_api_metrics, DatabaseQueryTimer, S3OperationTimer


logger = logging.getLogger(__name__)

############### start healthcheck apis ###############

@csrf_exempt 
@track_api_metrics
def health_check(request):
    print("Inside health_check API view...")

    if request.method != 'GET':
        response = HttpResponse(status=405) # Method Not Allowed
        logger.warning("Invalid method for health_check: %s", request.method)
        return response
    
    if request.body or request.GET:
        response = HttpResponse(status=400) # Bad Request if there's a payload
        logger.warning("Unexpected body or query params in health_check.")
        return response
    
    try:
        connection.ensure_connection() # check connection to db
        response = HttpResponse(status=200) # 200 OK if the connection is successful
        logger.info("Health check successful.")
    except Exception as e:
        logger.error("Database connection error in health_check: %s", str(e))
        response = HttpResponse(status=503) # Service Unavailable if there's a database error

    return response

def custom_404_view(request, exception):
    return HttpResponse(status=404)


############### start user apis ###############

@api_view(['GET', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD', 'POST'])
@track_api_metrics
def create_user(request):

    logger.info("Inside create_user API view...")

    try:
        connection.ensure_connection()
    except Exception as e:
        logger.error("Database connection error in create_user: %s", str(e))
        return HttpResponse(status=503)
    
    if request.method in ['GET', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD']:
        logger.error("Invalid method for create_user: %s", request.method)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    if 'HTTP_AUTHORIZATION' in request.META:
        logger.error("Authorization header not allowed for create_user.")
        return Response(status=status.HTTP_400_BAD_REQUEST)
    
    if request.GET or not request.body:
        logger.error("Invalid request for create_user.")
        return Response(status=status.HTTP_400_BAD_REQUEST)
    
    required_fields = {'email', 'password', 'first_name', 'last_name'}
    received_fields = set(request.data.keys())

    # Check if all required fields are present
    if not required_fields.issubset(received_fields):
        logger.error("All fields %s are required.", required_fields)
        return Response({'error': f'All fields {required_fields} are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if any extra fields are present
    if any(field not in required_fields for field in received_fields):
        logger.error("Only fields %s are allowed.", required_fields)
        return Response({'error': f'Only fields {required_fields} are allowed.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if all required fields have non-empty values
    for field in required_fields:
        value = request.data.get(field)
        if not value or value.strip() == '':
            logger.error("The field %s cannot be empty.", field)
            return Response({'error': f'The field {field} cannot be empty.'}, status=status.HTTP_400_BAD_REQUEST)
        if(field=='password' and len(value)<8):
            logger.error("Password should be atleast 8 charecters")
            return Response({'error': 'Password should be atleast 8 charecters'}, status=status.HTTP_400_BAD_REQUEST)
    
    email = request.data.get('email')
    password = request.data.get('password')
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')

    try:
        validate_email(email)
    except ValidationError:
        logger.error("Invalid email format: %s", email)
        return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        logger.error("A user with this email already exists: %s", email)
        return Response({'error': 'A user with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        with DatabaseQueryTimer('create_user'): 
            hashed_password = make_password(password)

            user = User.objects.create(
                email=email,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name
            )

        logger.info("User created successfully: %s", email)

        return Response({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'account_created': user.account_created,
            'account_updated': user.account_updated
        }, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        logger.error("Error creating user: %s", str(e))
        return Response({'error': 'Error creating user. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'OPTIONS', 'DELETE', 'PATCH', 'HEAD', 'POST'])
@track_api_metrics
def user_detail(request):

    logger.info("Inside user_detail API view...")

    try:
        connection.ensure_connection()
    except Exception as e:
        logger.error("Database connection error in user_detail: %s", str(e))
        return HttpResponse(status=503)
    
    if request.method in ['OPTIONS', 'DELETE', 'PATCH', 'HEAD', 'POST']:
        logger.error("Invalid method for user_detail: %s", request.method)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    if 'HTTP_AUTHORIZATION' not in request.META:
        logger.error("Authentication required for user_detail.")
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) != 2 or auth[0].lower() != "basic":
            logger.error("Invalid authorization header: %s", auth)
            return Response({'error': 'Invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)
        
        email, password = base64.b64decode(auth[1]).decode().split(':')
    except (IndexError, base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
        logger.error("Error decoding authorization header: %s", str(e))
        return Response({'error': 'Invalid authorization header'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        with DatabaseQueryTimer('get_user'):
            user = User.objects.get(email=email)
            logger.info("User found: %s", email)
    except User.DoesNotExist:
        logger.error("User not found: %s", email)
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if not check_password(password, user.password):
        logger.error("Invalid credentials for user: %s", email)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    
    if request.method == 'GET':
        return get_user_details(user, request)
    elif request.method == 'PUT':
        return update_user_details(user, request)


def get_user_details(user, request):

    logger.info("Inside get_user_details...")

    # do not allow body or query params
    if request.GET or request.body:
        logger.error("Invalid request for get_user_details.")
        return Response(status=status.HTTP_400_BAD_REQUEST)           
    
    try:
        logger.info("User details retrieved successfully: %s", user.email)
        return Response({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'account_created': user.account_created,
            'account_updated': user.account_updated
        })
    except Exception as e:
        logger.error("Error retrieving user details: %s", str(e))
        return Response({'error': 'Error retrieving user details'}, status=status.HTTP_400_BAD_REQUEST)

def update_user_details(user, request):

    logger.info("Inside update_user_details...")

    # do not allow query params
    if request.GET:
        logger.error("Invalid request for update_user_details.")
        return Response(status=status.HTTP_400_BAD_REQUEST)    
    
    allowed_fields = ["first_name", "last_name", "password"]
    received_fields = set(request.data.keys())

    # Check if atleast one field given for updation
    if not received_fields:
        logger.error("At least one field must be provided for update.")
        return Response({'error': 'At least one field must be provided for update'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if any extra fields are present
    if any(field not in allowed_fields for field in received_fields):
        logger.error("Only fields %s are allowed.", allowed_fields)
        return Response({'error': f'Only fields {allowed_fields} are allowed.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if all required fields have non-empty values
    for field in received_fields:
        value = request.data.get(field)
        if not value or value.strip() == '':
            logger.error("The field %s cannot be empty.", field)
            return Response({'error': f'The field {field} cannot be empty.'}, status=status.HTTP_400_BAD_REQUEST)
        if(field=='password' and len(value)<8):
            logger.error("Password should be atleast 8 charecters")
            return Response({'error': 'Password should be atleast 8 charecters'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        if 'first_name' in request.data:
            user.first_name = request.data['first_name']
        if 'last_name' in request.data:
            user.last_name = request.data['last_name']
        if 'password' in request.data:
            user.password = make_password(request.data['password'])

        user.save()
        logger.info("User details updated successfully: %s", user.email)

        return Response(status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        logger.error("Error updating user details: %s", str(e))
        return Response({'error': 'Error updating user details'}, status=status.HTTP_400_BAD_REQUEST)


############### start image apis ###############

from django.http import HttpResponse, JsonResponse
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

s3_client = boto3.client('s3') # initialize S3 client
# bucket_name = settings.S3_BUCKET_NAME
bucket_name = "myawsbucketbenny" # public s3 to test locally

def authenticate_user(request):

    logger.info("Inside authenticate_user...")
    
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
def profile_pic(request):
    
    logger.info("Inside profile_pic API view...")

    # Ensure database connection
    try:
        connection.ensure_connection()
    except Exception as e:
        logger.error("Database connection error: %s", str(e))
        return HttpResponse(status=503)

    # Authenticate user
    user, auth_error = authenticate_user(request)
    if auth_error:
        logger.error("Authentication failed: %s", auth_error)
        return JsonResponse({"error": auth_error}, status=status.HTTP_401_UNAUTHORIZED)

    # Upload a new image
    if request.method == 'POST':

        logger.info("Inside profile_pic POST...")

        if 'file' not in request.FILES:
            logger.error("No file provided")
            return JsonResponse({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        if Image.objects.filter(user_id=user).exists():
            logger.error("User already has an uploaded image")
            return JsonResponse({"error": "User already has an uploaded image"}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        file_type = uploaded_file.content_type

        # check if file type is acceptable
        ACCEPTABLE_IMAGE_TYPES = ["image/png", "image/jpeg", "image/jpg"]
        if file_type not in ACCEPTABLE_IMAGE_TYPES:
            logger.error("Invalid file type. Only PNG, JPG, and JPEG are allowed.")
            return JsonResponse({"error": "Invalid file type. Only PNG, JPG, and JPEG are allowed."}, status=status.HTTP_400_BAD_REQUEST)

        s3_key = f"{user.id}/{file_name}"
        try:
            with S3OperationTimer('upload_fileobj'):
                s3_client.upload_fileobj(uploaded_file, bucket_name, s3_key)
            url = f"s3://{bucket_name}/{s3_key}"
            logger.info("Image uploaded successfully in s3: %s", url)

            with DatabaseQueryTimer('create_image'):
                image = Image.objects.create(
                    file_name=file_name,
                    url=url,
                    user_id=user
                )
                logger.info("Image record created successfully in db: %s", image.id)

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

    # Retrieve an image
    elif request.method == 'GET':
        logger.info("Inside profile_pic GET...")
        try:
            with DatabaseQueryTimer('get_image'):
                image = Image.objects.get(user_id=user)
                logger.info("Image found: %s", image.id)
            return JsonResponse({
                "file_name": image.file_name,
                "id": image.id,
                "url": image.url,
                "uploaded_date": image.upload_date.strftime("%Y-%m-%d"),
                "user_id": str(image.user_id.id)
            }, status=status.HTTP_200_OK)
        except Image.DoesNotExist:
            logger.error("No image found for this user")
            return JsonResponse({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)

    # Delete an image
    elif request.method == 'DELETE':
        logger.info("Inside profile_pic DELETE...")
        try:
            with DatabaseQueryTimer('get_image_for_deletion'):
                image = Image.objects.get(user_id=user)
                logger.info("Image found for deletion: %s", image.id)
            with S3OperationTimer('delete_object'):
                s3_client.delete_object(Bucket=bucket_name, Key=image.url.split(f"{bucket_name}/")[-1])
                logger.info("Image deleted from s3: %s", image.url)
            with DatabaseQueryTimer('delete_image'): 
                image.delete()
                logger.info("Image record deleted successfully: %s", image.id)
            return HttpResponse(status=status.HTTP_204_NO_CONTENT)

        except Image.DoesNotExist:
            logger.error("No images found for this user")
            return JsonResponse({"error": "No images found for this user"}, status=status.HTTP_404_NOT_FOUND)
        except NoCredentialsError:
            logger.error("S3 credentials not available")
            return JsonResponse({"error": "S3 credentials not available"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error("Unexpected error during deletion: %s", str(e))
            return JsonResponse({"error": "Failed to delete image"}, status=status.HTTP_400_BAD_REQUEST)

    return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)

