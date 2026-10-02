# Reproducibility targets for the RSEP-XMSS reference shell.
#
# All measurement runs execute inside the canonical 2 CPU / 4 GiB container
# (matches the paper's sandbox environment). If your Docker requires sudo:
#   make DOCKER="sudo docker" test
#
# Override the constraint knobs if you need a different environment:
#   make CPUS=8 MEM=16g measure

IMAGE  ?= vmc-repro
DOCKER ?= docker
CPUS   ?= 2
MEM    ?= 4g
H      ?= 10
RUN     = $(DOCKER) run --rm --cpus=$(CPUS) --memory=$(MEM) -v "$(PWD)/out:/work/out" $(IMAGE)

.PHONY: image test measure measure-all cusum wf-audit reproduce-all clean

image:
	$(DOCKER) build -t $(IMAGE) .

test: image
	$(RUN) cargo test --release

measure: image
	mkdir -p out
	$(RUN) cargo run --release --example measure -- $(H) 5

measure-all: image
	mkdir -p out
	$(RUN) sh -c 'for h in 10 12 16; do cargo run --release --example measure -- $$h 5 | tee out/measure-v4-h$$h.log; done'

cusum: image
	mkdir -p out
	$(RUN) sh -c 'python3 statistics/cusum_mc.py > out/cusum-output.txt && python3 statistics/verify.py out/cusum-output.txt statistics/expected_output.txt'

wf-audit: image
	$(RUN) sh -c 'cd rsep-pq-shell/wf-audit && cargo run --release'

reproduce-all: test cusum measure-all wf-audit

clean:
	rm -rf out
