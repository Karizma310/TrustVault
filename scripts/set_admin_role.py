import argparse
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import get_engine, initialize_database
from app.models.user import User
from app.services.audit import record_event


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Promote or demote an existing TrustVault account using trusted local access."
    )
    parser.add_argument("email", help="Registered account email")
    parser.add_argument("--demote", action="store_true", help="Change the account back to a regular user")
    parser.add_argument(
        "--only-admin",
        action="store_true",
        help="Promote this account and demote any other administrators",
    )
    args = parser.parse_args()
    if args.demote and args.only_admin:
        parser.error("--demote and --only-admin cannot be used together")

    initialize_database()
    with Session(get_engine()) as db:
        user = db.scalar(select(User).where(User.email == args.email.casefold()))
        if user is None:
            raise SystemExit("No account is registered with that email.")
        role = "user" if args.demote else "admin"
        changed_users = []
        if args.only_admin:
            other_admins = db.scalars(
                select(User).where(User.role == "admin", User.id != user.id)
            )
            for other_admin in other_admins:
                other_admin.role = "user"
                changed_users.append((other_admin, "user"))
        if user.role != role:
            user.role = role
            changed_users.append((user, role))
        if not changed_users:
            print(f"Account already has the {role} role.")
            return
        for changed_user, new_role in changed_users:
            record_event(
                db,
                actor_user_id=None,
                action="admin_role_changed",
                resource_type="user",
                resource_id=str(changed_user.id),
                details={"new_role": new_role},
            )
        db.commit()
        print(f"Updated {len(changed_users)} account role(s).")


if __name__ == "__main__":
    main()
