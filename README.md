# Description
This project requires two entities: prover and verifier. Prover is I.MX6-SabreLite while verifier is a powerful Windows machine.

HYDRA is published at WiSec'17. If you plan to use any part of our HYDRA code, please consider citing:

```
@inproceedings{eldefrawy2017hydra,
  title={HYDRA: hybrid design for remote attestation (using a formally verified microkernel)},
  author={Eldefrawy, Karim and Rattanavipanon, Norrathep and Tsudik, Gene},
  booktitle={Proceedings of the 10th ACM Conference on Security and Privacy in Wireless and Mobile Networks},
  pages={99--110},
  year={2017},
  organization={ACM}
}
```

ASSURED is accepted as a publication at EMSOFT'18.

```
@inproceedings{asokan2018assured,
  title={ASSURED: Architecture for Secure Software Update of Realistic Embedded Devices},
  author={Asokan, N and Nyman, Thomas and Rattanavipanon, Norrathep and Sadeghi, Ahmad-Reza and Tsudik, Gene},
  booktitle={EMSOFT},
  year={2018}
}
```

# Prover

## SW-UPDATE:

Source code:
```
prover/apps/dhs-demo: main software update framework
prover/apps/fuel-level-app and prover/apps/speedometer-app: updatable user-space processes
```

To compile:

```
cp configs/sw-update-image-imx6 .config
make clean && make
cd sel4-stripimage
make run
```

To run on SabreLite:
Assume (i) micro-sd is inserted at /dev/sdX and (ii) the SabreLite board is configured to be able to run seL4 executable (if not, visit: https://sel4.systems/Info/Hardware/sabreLite/)
1) `dd if=fuel-level-app of=/dev/sdX bs=512 seek=2048`

2) `dd if=speedometer-app of=/dev/sdX bs=512 seek=4096`

3) Manually copy 'dhs-demo-image-arm-imx6' into micro-sd and insert micro-sd back to the SabreLite board
4) Try to boot I.MX6-SabreLite with ethernet cable attached, interrupt using the spacebar, then type the following commands:

```
mmc dev 1
fatload mmc 1 ${loadaddr} dhs-demo-image-arm-imx6
bootelf ${loadaddr}
```

WARNING: In my case, it seems like the MMC driver does not work properly, so I have to load the executable to RAM from dev 0 slot (an SD slot).

So the first two steps change to: 4.1) `mmc dev 0`, 4.2) `fatload mmc 0 ${loadaddr} dhs-demo-image-arm-imx6`
Then switch the micro-sd card to dev 1 slot and run 4.3)

Note that this version implements a software update framework based on a modified TUF verification on seL4;
it DOES NOT implement ASSURED. 

## SW-UPDATE-BENCHMARK (ASSURED)

Source code:
```
prover/apps/update-benchmark
```

To compile
```
cp configs/sw-update-benchmark-image-imx6 .config
make clean && make
```

To run on SabreLite:
1) Manually copy 'update-benchmark-image-arm-imx6' into micro-sd and insert micro-sd back to the SabreLite board
2) Try to boot I.MX6-SabreLite, interrupt using the spacebar, then type the following commands:

```
mmc dev 1
fatload mmc 1 ${loadaddr} update-benchmark-image-arm-imx6
bootelf ${loadaddr}
```

It contains a proof-of-concept of the ASSURED implementation that can be run on I.MX6-SabreLite.
It is only used for benchmarking purposes only as there is no verifier code to support it yet.


## ATTESTATION (HYDRA):

Source code:
```
prover/apps/hydra: main attestation framework
prover/apps/hydra-app: target process for attestation
```

To compile:
```
cp configs/hydra-attest-image-imx6 .config
make clean
make
```

To run on SabreLite:
1) Manually copy 'hydra-image-arm-imx6' into micro-sd and insert micro-sd back to the SabreLite board
2) Try to boot I.MX6-SabreLite, interrupt using the spacebar, then type the following commands:

```
mmc dev 1
fatload mmc 1 ${loadaddr} hydra-image-arm-imx6
bootelf ${loadaddr}
```



# Verifier

The verifier requires Visual Studio 2015 on Windows 10.

1) Configure ethernet IP of the verifier machine to 192.168.168.1
2) Run both UDP-test and windows_verifier projects, follow their instructions

# License
GPLv2 see `LICENSE` for more details.
