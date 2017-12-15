FPS KSM implemented in Javascript
=========================
Key Security Module written to run in NodeJS

### Files for test
1. SPC/CKC folder: `~/.data/FPS`
    - This folder contains: `spc1.bin`, `spc2.bin`, `spc3.bin`, `ckc1.bin`, `ckc2.bin`, `ckc3.bin`, `MD5.txt`
2. Development credentials: 
    - `~/.data/dev_certificate.der`
    - `~/.data/dev_private_key.pem`

### Typical server program steps

|Task No.| Task          | Status           | Files  |
|--------| ------------- |----------------| ------:|
|   1    |Receive an SPC message from an app running on an Apple device and parse it. See The SPC Message.| Not yet |-|
|   2    |Check the SPC's certificate hash value against the AC.| Not yet |-|
|   3    |Decrypt the SPC payload.| Not yet |-|
|   4    |Verify that the Apple device is using a supported version of FPS software.| Not yet |-|
|   5    |Decrypt the session key and random value block in the SPC payload.| Not yet |-|
|   6    |Check the integrity of the SPC message. See Session Key and Random Value Integrity Block.| Not yet |-|
|   7    |Encrypt the content key.| Not yet |-|
|   8    |Assemble the contents of the CKC payload.| Not yet |-|
|   9    |Encrypt the CKC payload.| Not yet |-|
|   10   |Construct the CKC message and send it to the app on the Apple device.| Not yet |-|


### CONSTANT FILES
- Located in: `src/constant.js`
- Purpose: Store const written in c.


