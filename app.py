import psycopg
import os
from dotenv import load_dotenv

# Load environment variables if using a .env file
load_dotenv()

# Database configuration - update with your actual credentials
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://red_db_user:08PP2B2lSy2GAD5H7Jp51XRbrzldYOZB@dpg-d32s8gur433s73bavsvg-a.oregon-postgres.render.com/red_db')

def get_all_users():
    """Retrieve all users from the database"""
    try:
        # Connect to the database
        conn = psycopg.connect(DATABASE_URL)
        
        # Create a cursor
        with conn.cursor() as cur:
            # Execute the query to get all users
            cur.execute('SELECT id, username, email, created_at FROM users ORDER BY id')
            
            # Fetch all results
            users = cur.fetchall()
            
            # Print the results
            print(f"Found {len(users)} users:")
            print("-" * 80)
            for user in users:
                print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Created: {user[3]}")
            
        # Close the connection
        conn.close()
        
        return users
        
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

if __name__ == "__main__":
    print("Testing database connection and retrieving users...")
    get_all_users()
