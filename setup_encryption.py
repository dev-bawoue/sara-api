#!/usr/bin/env python3
"""
Setup script to generate encryption key for ID encryption
Run this before deploying to generate a secure encryption key
"""

from cryptography.fernet import Fernet
import base64
import os

def generate_encryption_key():
    """Generate a new encryption key for ID encryption."""
    key = Fernet.generate_key()
    key_b64 = base64.b64encode(key).decode()
    
    print(" Generated new encryption key for ID encryption")
    print("=" * 50)
    print(f"ID_ENCRYPTION_KEY={key_b64}")
    print("=" * 50)
    print("  IMPORTANT: Save this key securely!")
    print("- Add it to your environment variables")
    print("- Store it in Google Secret Manager for Cloud Run")
    print("- Never commit this key to version control")
    print("- If you lose this key, existing encrypted IDs cannot be decrypted")
    
    return key_b64

def update_env_file(key):
    """Update .env file with the new key."""
    env_file = ".env"
    env_example = ".env.example"
    
    if os.path.exists(env_file):
        # Read existing .env file
        with open(env_file, 'r') as f:
            lines = f.readlines()
        
        # Update or add the encryption key
        updated = False
        for i, line in enumerate(lines):
            if line.startswith('ID_ENCRYPTION_KEY='):
                lines[i] = f'ID_ENCRYPTION_KEY={key}\n'
                updated = True
                break
        
        if not updated:
            lines.append(f'ID_ENCRYPTION_KEY={key}\n')
        
        # Write back to .env file
        with open(env_file, 'w') as f:
            f.writelines(lines)
        
        print(f" Updated {env_file} with new encryption key")
    else:
        print(f"ℹ  No {env_file} file found. Please add the key manually.")

def create_gcloud_secret(key, project_id=None):
    """Create Google Cloud Secret for the encryption key."""
    if not project_id:
        project_id = input("Enter your Google Cloud Project ID (or press Enter to skip): ").strip()
    
    if not project_id:
        print("Skipping Google Cloud Secret creation")
        return
    
    try:
        import subprocess
        
        # Create the secret
        cmd = [
            'gcloud', 'secrets', 'create', 'ID_ENCRYPTION_KEY',
            '--project', project_id,
            '--data-file', '-'
        ]
        
        result = subprocess.run(
            cmd,
            input=key.encode(),
            capture_output=True,
            text=False
        )
        
        if result.returncode == 0:
            print(f" Created Google Cloud Secret 'ID_ENCRYPTION_KEY' in project {project_id}")
        else:
            if "already exists" in result.stderr.decode():
                print(f"ℹ  Secret 'ID_ENCRYPTION_KEY' already exists in project {project_id}")
                
                # Update existing secret
                update_cmd = [
                    'gcloud', 'secrets', 'versions', 'add', 'ID_ENCRYPTION_KEY',
                    '--project', project_id,
                    '--data-file', '-'
                ]
                
                update_result = subprocess.run(
                    update_cmd,
                    input=key.encode(),
                    capture_output=True,
                    text=False
                )
                
                if update_result.returncode == 0:
                    print(f" Updated Google Cloud Secret 'ID_ENCRYPTION_KEY' in project {project_id}")
                else:
                    print(f" Failed to update secret: {update_result.stderr.decode()}")
            else:
                print(f" Failed to create secret: {result.stderr.decode()}")
                
    except subprocess.CalledProcessError as e:
        print(f" Error running gcloud command: {e}")
    except ImportError:
        print("  subprocess not available, skipping Google Cloud Secret creation")
    except Exception as e:
        print(f" Error creating Google Cloud Secret: {e}")

def main():
    print(" SARA API Encryption Setup")
    print("=" * 30)
    
    # Generate new encryption key
    key = generate_encryption_key()
    
    # Ask if user wants to update .env file
    update_env = input("\nUpdate .env file with new key? (y/N): ").lower().strip()
    if update_env in ['y', 'yes']:
        update_env_file(key)
    
    # Ask if user wants to create Google Cloud Secret
    create_secret = input("\nCreate Google Cloud Secret for deployment? (y/N): ").lower().strip()
    if create_secret in ['y', 'yes']:
        create_gcloud_secret(key, "precise-equator-274319")
    
    print("\n Encryption setup complete!")
    print("\nNext steps:")
    print("1. Make sure the encryption key is set in your deployment environment")
    print("2. Update your Cloud Run service with the new secret")
    print("3. Deploy your application")
    
    print("\n  Security reminder:")
    print("- Keep this encryption key secure and backed up")
    print("- Use the same key across all environments")
    print("- Never commit the key to version control")

if __name__ == "__main__":
    main()