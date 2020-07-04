![pubcFS general diagram](https://github.com/miromannino/pubcFS/raw/master/docs/general-diagram.png)

pubcFS is a virtual file system that encrypts folders and files on-the-fly. It uses asymmetric keys (i.e. RSA) in order to make it possible to share the encrypted folders with other users.

It is implemented in C, using FUSE, which make it possible to install this filesystem in the userspace rather than in kernel space. 

## Motivations

Cloud storage services (e.g. Dropbox, Amazon S3, Ubuntu One, 4shared, DivShare, or ADrive) often encrypt a user's files using his/her account password, but it is unclear how these encrypted files can be shared to other users. If the user's account password is used in order to encrypt files, how other users can decrypt shared files?

Solution to this problem relies on the actual cloud storage service, but can they be trusted?

This project aim to solve this potential security issue by allowing users to encrypt and decrypt files even before they are even stored to a cloud storage service.

## Why a virtual file system?

Famous file systems are readily available in our operating systems, but file systems like these might be hard to be included in a official Linux distro, or in operating systems such as MacOS or Windows.

For this reason a virtual file system is created for pubcFS. In this way users can easily install it as any other application, while performances anyway comparable to a native file system.

## Compile

TODO

In order to compile the following packages are needed:

 - libssl-dev
