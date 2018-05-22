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


# PROVER: In prover folder

## SW-UPDATE:

To compile:

1) cp configs/sw-update-image-imx6 .config
2) make clean && make
3) cd sel4-stripimage
4) make run

To run on SabreLite:
Assume (i) micro-sd is inserted at /dev/sdX and (ii) the SabreLite board is configured to be able to run seL4 executable (if not, visit: https://sel4.systems/Info/Hardware/sabreLite/)
1) dd if=fuel-level-app of=/dev/sdX bs=512 seek=2048
2) dd if=speedometer-app of=/dev/sdX bs=512 seek=4096
3) Manually copy 'dhs-demo-image-arm-imx6' into micro-sd and insert micro-sd back to the SabreLite board
4) Try to boot I.MX6-SabreLite, interrupt using the spacebar, then type the following commands:
4.1) mmc dev 1
4.2) fatload mmc 1 ${loadaddr} dhs-demo-image-arm-imx6
4.3) bootelf ${loadaddr}
4.4) connect ethernet cable with verifier
WARNING: In my case, it seems like the MMC driver does not work properly, so I have to load the executable to RAM from dev 0 slot (an SD slot).
So the first two steps change to: 4.1) mmc dev 0, 4.2) fatload mmc 0 ${loadaddr} dhs-demo-image-arm-imx6
Then switch the micro-sd card to dev 1 slot and run 4.3)



## ATTESTATION (HYDRA):

To compile:
1) cp configs/hydra-attest-image-imx6
2) make clean
3) make

To run on SabreLite:
1) Manually copy 'hydra-image-arm-imx6' into micro-sd and insert micro-sd back to the SabreLite board
2) Try to boot I.MX6-SabreLite, interrupt using the spacebar, then type the following commands:
2.1) mmc dev 1
2.2) fatload mmc 1 ${loadaddr} hydra-image-arm-imx6
2.3) bootelf ${loadaddr}



# VERIFIER(for both SW-UPDATE and HYDRA): In verifier folder

The verifier requires Visual Studio 2015 on Windows 10.

1) Configure ethernet IP of the verifier machine to 192.168.168.1
2) Run both UDP-test and windows_verifier projects, follow its instructions

