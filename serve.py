from wsgiref.simple_server import make_server

from app import app, ensure_database_ready


if __name__ == "__main__":
    with app.app_context():
        ensure_database_ready()

    server = make_server("127.0.0.1", 5000, app)
    print("Secure File Vault running at http://127.0.0.1:5000")
    server.serve_forever()
