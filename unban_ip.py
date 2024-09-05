from app import db, BannedIP
import sys

def unban_ip(ip_id):
    """주어진 ID의 차단된 IP를 해제하는 함수"""
    banned_ip = BannedIP.query.get(ip_id)
    if banned_ip:
        db.session.delete(banned_ip)
        db.session.commit()
        print(f"IP {banned_ip.ip_address} has been unbanned.")
    else:
        print("IP not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unban_ip.py <ip_id>")
        sys.exit(1)

    try:
        ip_id = int(sys.argv[1])
    except ValueError:
        print("IP ID must be an integer.")
        sys.exit(1)

    from app import app  # import app here to ensure app context is set
    with app.app_context():
        unban_ip(ip_id)

