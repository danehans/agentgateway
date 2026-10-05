#!/usr/bin/env python3
"""Run the real gateway, gRPC router, and mock inference service on temporary ports."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(number, process):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError(f"process exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", number), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {number} did not become ready")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="target/ci/agentgateway")
    parser.add_argument("--router", default="target/ci/examples/grpc-model-router")
    args = parser.parse_args()
    gateway_port, router_port, inference_port = port(), port(), port()
    config = Path(__file__).with_name("config.yaml").read_text()
    config = config.replace("port: 4000", f"port: {gateway_port}")
    config = config.replace("127.0.0.1:50051", f"127.0.0.1:{router_port}")
    config = config.replace("127.0.0.1:3001", f"127.0.0.1:{inference_port}")
    env = dict(os.environ, GRPC_ROUTER_ADDR=f"127.0.0.1:{router_port}",
               MOCK_INFERENCE_ADDR=f"127.0.0.1:{inference_port}",
               ADMIN_ADDR="127.0.0.1:0", STATS_ADDR="127.0.0.1:0", READINESS_ADDR="127.0.0.1:0")
    processes = []
    with tempfile.TemporaryDirectory(prefix="grpc-routing-") as directory:
        config_path = Path(directory) / "config.yaml"
        config_path.write_text(config)
        with (Path(directory) / "processes.log").open("w+") as log:
            try:
                router = subprocess.Popen([str(Path(args.router).resolve())], env=env, stdout=log, stderr=log)
                processes.append(router)
                wait_port(router_port, router)
                gateway = subprocess.Popen([str(Path(args.gateway).resolve()), "-f", str(config_path)], env=env, stdout=log, stderr=log)
                processes.append(gateway)
                wait_port(gateway_port, gateway)

                def request(text, stream=False, model="auto"):
                    data = json.dumps({"model": model, "stream": stream,
                                       "messages": [{"role": "user", "content": text}]}).encode()
                    req = urllib.request.Request(f"http://127.0.0.1:{gateway_port}/v1/chat/completions", data,
                                                 {"Content-Type": "application/json"})
                    try:
                        response = urllib.request.urlopen(req, timeout=10)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        return response.status, response.read().decode()

                for text, expected in [("hello", "economy-model"), ("complex", "premium-model"), ("outage", "economy-model")]:
                    status, body = request(text)
                    assert status == 200, (status, body)
                    assert json.loads(body)["model"] == expected, body
                status, body = request("conflict")
                assert status == 409 and "session_conflict" in body, (status, body)
                status, body = request("complex", stream=True)
                assert status == 200 and "[DONE]" in body and "premium-model" in body, (status, body)
                status, body = request("hello", model="premium-model")
                assert status == 404, (status, body)
                print("PASS: model selection, fallback, rejection, SSE, internal-model access")
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                for process in reversed(processes):
                    process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
