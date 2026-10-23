import unittest

from TrustVault_app_updated import app


class TrustVaultSecurityTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def login(self, username, password):
        # Prepare CSRF token for the application's security check
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-token"

        return self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": "test-token",
            },
            follow_redirects=True,
        )

    def test_login_page_is_available(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)

    def test_invalid_login_is_rejected(self):
        response = self.login("wronguser", "WrongPassword123")
        self.assertNotIn(b"Welcome, wronguser!", response.data)
        self.assertIn(
            b"Invalid username or password",
            response.data,
        )

    def test_admin_login(self):
        response = self.login("admin", "Admin@12345")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, admin!", response.data)

    def test_owner_login(self):
        response = self.login("owner", "Owner@12345")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, owner!", response.data)

    def test_viewer_login(self):
        response = self.login("viewer", "Viewer@12345")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, viewer!", response.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)