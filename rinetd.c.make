test -f config.h || rm -f stamp-h1
test -f config.h || make  stamp-h1
make  all-am
test -f config.h || rm -f stamp-h1
test -f config.h || make  stamp-h1
gcc -DHAVE_CONFIG_H -I.    -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2 -MT rinetd-rinetd.o -MD -MP -MF .deps/rinetd-rinetd.Tpo -c -o rinetd-rinetd.o `test -f 'rinetd.c' || echo './'`rinetd.c
mv -f .deps/rinetd-rinetd.Tpo .deps/rinetd-rinetd.Po
gcc -DHAVE_CONFIG_H -I.    -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2 -MT rinetd-match.o -MD -MP -MF .deps/rinetd-match.Tpo -c -o rinetd-match.o `test -f 'match.c' || echo './'`match.c
mv -f .deps/rinetd-match.Tpo .deps/rinetd-match.Po
rm -f rinetd
gcc -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2   -o rinetd rinetd-rinetd.o rinetd-match.o  
