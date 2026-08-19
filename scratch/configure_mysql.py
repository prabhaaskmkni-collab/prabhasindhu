import paramiko

def configure():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('200.97.165.171', username='root', password='Socialmedia@odd2026#', timeout=10)
        
        sql_commands = (
            "ALTER USER 'mockup_user'@'localhost' IDENTIFIED BY 'Socialmedia@odd2026#'; "
            "GRANT ALL PRIVILEGES ON mockup_engine.* TO 'mockup_user'@'localhost'; "
            "FLUSH PRIVILEGES;"
        )
        
        # Write to a file on the remote server
        stdin, stdout, stderr = ssh.exec_command(f'echo "{sql_commands}" > /tmp/setup_db.sql')
        stdout.read()
        
        # Run mysql with the file
        stdin, stdout, stderr = ssh.exec_command('mysql < /tmp/setup_db.sql')
        out = stdout.read().decode('utf-8')
        err = stderr.read().decode('utf-8')
        
        print("STDOUT:", out)
        print("STDERR:", err)
        print("Completed MySQL configuration.")
        
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    configure()
