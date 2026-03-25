import socket
import struct
import time
import argparse


def parse_icmp(packet: bytes):

    if len(packet) < 28:
        return None, None

    ip_header_len = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_len + 8:
        return None, None

    icmp_header = packet[ip_header_len:ip_header_len + 8]
    icmp_type, icmp_code, _, _ = struct.unpack("!BBHI", icmp_header)

    return icmp_type, icmp_code


def traceroute(destination_ip: str, max_hops: int = 30, probes: int = 3, timeout: float = 2.0):
    print(f"traceroute to {destination_ip}, {max_hops} hops max")

    base_port = 33434

    for ttl in range(1, max_hops + 1):
        print(f"{ttl:2d} ", end="", flush=True)

        hop_ip = None
        reached = False

        for probe in range(probes):
            recv_sock = None
            send_sock = None

            try:

                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                recv_sock.settimeout(timeout)


                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

                payload = b"test"
                port = base_port + ttl + probe

                start_time = time.time()
                send_sock.sendto(payload, (destination_ip, port))

                packet, addr = recv_sock.recvfrom(512)
                elapsed = (time.time() - start_time) * 1000

                hop_ip = addr[0]
                icmp_type, icmp_code = parse_icmp(packet)

                print(f"{elapsed:7.2f} ms ", end="", flush=True)

                if icmp_type == 3 and icmp_code == 3:
                    reached = True

            except socket.timeout:
                print("* ", end="", flush=True)

            except PermissionError:
                print("\nОшибка: нужны права администратора.")
                print("На macOS запускай так:")
                print("sudo python3 mytraceroute.py 8.8.8.8")
                return

            except Exception as e:
                print(f"ошибка ", end="", flush=True)

            finally:
                if send_sock:
                    send_sock.close()
                if recv_sock:
                    recv_sock.close()

        if hop_ip:
            print(hop_ip)
        else:
            print()

        if reached:
            break


def main():
    parser = argparse.ArgumentParser(description="Простой traceroute на Python")
    parser.add_argument("ip", help="IP-адрес целевого узла")
    args = parser.parse_args()

    traceroute(args.ip)


if __name__ == "__main__":
    main()