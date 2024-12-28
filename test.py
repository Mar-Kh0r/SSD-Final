import requests
from bs4 import BeautifulSoup

BASE_URL = "http://127.0.0.1:8080"

def get_csrf_token(session, endpoint):
    """
    Fetch CSRF token from the given endpoint.
    """
    response = session.get(BASE_URL + endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
    return csrf_token

def test_rate_limiting_with_csrf(endpoint, payload=None):
    """
    Test the rate limiting for a given endpoint with CSRF token.
    """
    with requests.Session() as session:
        for i in range(7):  # Attempt more requests than the rate limit
            try:
                # Get CSRF token for each request
                csrf_token = get_csrf_token(session, endpoint)
                if payload is None:
                    payload = {}
                payload['csrf_token'] = csrf_token

                # Perform the request
                response = session.post(BASE_URL + endpoint, data=payload)
                if response.status_code == 429:  # Too Many Requests
                    print(f"Request {i + 1}: Rate limit exceeded (429)")
                else:
                    print(f"Request {i + 1}: Status {response.status_code}, Response: {response.text}")
            except Exception as e:
                print(f"Request {i + 1}: Error occurred - {str(e)}")

# Test the /signup route
print("Testing /signup route:")
test_rate_limiting_with_csrf("/signup", payload={
    "name": "Test User",
    "email": "testuser@example.com",
    "password": "password123",
    "confirm_password": "password123"
})

# Test the /login route
print("\nTesting /login route:")
test_rate_limiting_with_csrf("/login", payload={
    "email": "testuser@example.com",
    "password": "password123"
})
