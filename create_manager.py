import os
from dotenv import load_dotenv
from supabase import create_client


def main() -> None:
    load_dotenv()
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        raise ValueError("Missing SUPABASE_URL or SUPABASE_KEY in .env")

    # Credentials requested by user
    email = "manager.new@leaveflow.local"
    password = "Manager@12345"

    client = create_client(url, key)
    result = client.auth.sign_up({"email": email, "password": password})

    print("Created manager user:")
    print(f"email={email}")
    print(f"password={password}")
    print(f"user_id={getattr(result.user, 'id', None)}")


if __name__ == "__main__":
    main()
