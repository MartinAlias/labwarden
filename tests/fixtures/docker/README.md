Docker Engine API responses (as served through docker-socket-proxy) used by `tests/test_docker.py`.

Written from the Docker Engine API reference and trimmed to the fields the collector reads; not
recorded from a live host. `FIXTURE-SECRET-DO-NOT-LEAK` marks env vars and labels that must
never reach the Lab Model. When recording real responses, scrub `Config.Env` and `Config.Labels`.
