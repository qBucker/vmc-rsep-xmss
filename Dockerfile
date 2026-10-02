# Reproducibility container for the RSEP-XMSS reference shell.
#
# Canonical measurement environment: 2 CPUs / 4 GiB — chosen to match the
# environment description of the paper's sandbox rows (Table 3 caption:
# "2-core sandbox, 4 GB RAM"). Verified with:
#
#   docker build -t vmc-repro .
#   docker run --rm --cpus=2 --memory=4g vmc-repro cargo test --release
#
# or simply: make test / make measure / make cusum  (see Makefile).

FROM rust:1.98.1-bookworm

# Python + NumPy for the statistical-layer artifact (statistics/cusum_mc.py)
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-numpy \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . .

# Pre-build dependencies / test and example targets (cached layer).
RUN cargo build --release --tests --examples

CMD ["cargo", "test", "--release"]
