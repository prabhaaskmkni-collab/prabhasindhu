import sys
import paramiko

def run_ssh_command(cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('200.97.165.171', username='root', password='Socialmedia@odd2026#', timeout=10)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read()
        err = stderr.read()
        
        # Write binary stdout/stderr to files
        with open('scratch/ssh_output.txt', 'wb') as f:
            f.write(out)
        with open('scratch/ssh_error.txt', 'wb') as f:
            f.write(err)
            
        print("Success. Written to scratch/ssh_output.txt and scratch/ssh_error.txt")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_ssh_command(sys.argv[1])
    else:
        print("No command provided")
