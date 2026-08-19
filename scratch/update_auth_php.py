import paramiko

def update_auth_php():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('200.97.165.171', username='root', password='Socialmedia@odd2026#', timeout=10)
        
        # Read the file
        sftp = ssh.open_sftp()
        filepath = '/var/www/mockup-engine/auth.php'
        
        with sftp.file(filepath, 'r') as f:
            content = f.read().decode('utf-8')
            
        # Replace the database credentials
        updated_content = content.replace("define('DB_NAME',     'YOUR_DB_NAME');", "define('DB_NAME',     'mockup_engine');")
        updated_content = updated_content.replace("define('DB_USER',     'YOUR_DB_USER');", "define('DB_USER',     'mockup_user');")
        updated_content = updated_content.replace("define('DB_PASS',     'YOUR_DB_PASSWORD');", "define('DB_PASS',     'Socialmedia@odd2026#');")
        
        # Write back the file
        with sftp.file(filepath, 'w') as f:
            f.write(updated_content.encode('utf-8'))
            
        print("Successfully updated auth.php on remote server.")
        
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    update_auth_php()
