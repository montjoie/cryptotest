#!/bin/sh

if [ -e /usr/src/kernels ];then
	cd /usr/src
	X=$(ls kernels/)
	ln -s kernels/$X linux
	exit 0
fi

ls -l /usr/src/
FKSRC=$(find /usr/src/ -iname *tar.xz)
DKSRC=$(echo $FKSRC | sed 's,.tar.xz,,')
cd /usr/src
tar xJf $FKSRC || exit $?
ln -s $DKSRC linux
ls -l

DCONFIG=$(find /usr/src/ -iname 'linux-config*')
cd $DCONFIG
xzcat config.amd64_none_amd64.xz > /usr/src/linux/.config
cd /usr/src/linux
make oldconfig || exit $?
make prepare || exit $?
make modules_prepare || exit $?
