from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from .models import User
from django.contrib.auth.hashers import make_password, check_password
import base64
from unittest.mock import patch

class UserAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.create_user_url = reverse('create_user')
        self.user_detail_url = reverse('user_detail')
        self.test_user = User.objects.create(
            email='testuser@gmail.com',
            password=make_password('testpassword'),
            first_name='Test',
            last_name='User'
        )
        User.objects.filter(email='testuser@gmail.com').update(is_verified=True)

    # start tests for create user

    @patch('backend_api.views.sns_client.publish')
    def test_create_user_success(self, mock_publish):
        mock_publish.return_value = {'MessageId': 'mock-message-id'}
        data = {
            'email': 'newuser@gmail.com',
            'password': 'newpassword',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(self.create_user_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(response.data['email'], 'newuser@gmail.com')

    def test_create_user_missing_field(self):
        data = {
            'email': 'newuser@gmail.com',
            'password': 'newpassword',
            'first_name': 'New'
        }
        response = self.client.post(self.create_user_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_invalid_email(self):
        data = {
            'email': 'invalidemail',
            'password': 'newpassword',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(self.create_user_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_duplicate_email(self):
        data = {
            'email': 'testuser@gmail.com',
            'password': 'newpassword',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(self.create_user_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_with_extra_field(self):
        data = {
            'email': 'newuser@gmail.com',
            'password': 'newpassword',
            'first_name': 'New',
            'last_name': 'User',
            'extraaa': 'extraaa'
        }
        response = self.client.post(self.create_user_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_with_whitespace_only_fields(self):
        data = {
            'email': 'newuser@gmail.com',
            'password': 'newpassword',
            'first_name': '   ',
            'last_name': '\t\n'
        }
        response = self.client.post(self.create_user_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # end tests for create user

    # start tests for get user

    def test_get_user_details_success(self):
        credentials = base64.b64encode(b'testuser@gmail.com:testpassword').decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        response = self.client.get(self.user_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'testuser@gmail.com')

    def test_get_user_details_unauthorized(self):
        response = self.client.get(self.user_detail_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_user_details_invalid_credentials(self):
        credentials = base64.b64encode(b'testuser@gmail.com:wrongggpassword').decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        response = self.client.get(self.user_detail_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # end tests for get user

    # start tests for update user

    def test_update_user_details_success(self):
        credentials = base64.b64encode(b'testuser@gmail.com:testpassword').decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        data = {
            'first_name': 'Name2',
            'last_name': 'Last2'
        }
        response = self.client.put(self.user_detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # Verify the details got updated
        updated_user = User.objects.get(email='testuser@gmail.com')
        self.assertTrue(updated_user.first_name, data['first_name'])
        self.assertTrue(updated_user.last_name, data['last_name'])

    def test_update_user_details_invalid_field(self):
        credentials = base64.b64encode(b'testuser@gmail.com:testpassword').decode('utf-8')
        self.client.credentials(HTTP_AUTHORIZATION=f'Basic {credentials}')
        data = {
            'email': 'newemail@gmail.com'
        }
        response = self.client.put(self.user_detail_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # end tests for update user