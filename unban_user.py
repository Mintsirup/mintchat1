from app import db, User
import sys

def unban_user(user_id):
    """주어진 ID의 사용자의 밴을 해제하는 함수"""
    user = User.query.get(user_id)
    if user:
        user.banned = False
        db.session.commit()
        print(f"User {user.username} has been unbanned.")
    else:
        print("User not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unban_user.py <user_id>")
        sys.exit(1)

    try:
        user_id = int(sys.argv[1])
    except ValueError:
        print("User ID must be an integer.")
        sys.exit(1)

    from app import app  # import app here to ensure app context is set
    with app.app_context():
        unban_user(user_id)

