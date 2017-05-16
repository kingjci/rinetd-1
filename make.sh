
# gcc -Wp,-MD,/home/vagrant/lkl/linux/tools/lkl/tests/.net-test.o.d -Wp,-MT,/home/vagrant/lkl/linux/tools/lkl/tests/net-test.o -I/home/vagrant/lkl/linux/tools/lkl//include -Iinclude -Wall -g -O2 -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fno-strict-aliasing -fPIC -pthread -DCONFIG_AUTO_LKL_POSIX_HOST -D"BUILD_STR(s)=#s" -c -o /home/vagrant/lkl/linux/tools/lkl/tests/net-test.o tests/net-test.c
# gcc -I/home/vagrant/lkl/linux/tools/lkl/include -O2 -fPIC -DCONFIG_AUTO_LKL_POSIX_HOST -c -o /home/vagrant/lkl/linux/tools/lkl/tests/net-test.o net-test.c
# ld -r -o /home/vagrant/lkl/linux/tools/lkl/tests/net-test-in.o  /home/vagrant/lkl/linux/tools/lkl/tests/net-test.o
# gcc  -o /home/vagrant/lkl/linux/tools/lkl/tests/net-test /home/vagrant/lkl/linux/tools/lkl/tests/net-test-in.o /home/vagrant/lkl/linux/tools/lkl/liblkl.a -lrt -lpthread
# 
# gcc -DHAVE_CONFIG_H -I.    -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2 -MT rinetd-rinetd.o -MD -MP -MF .deps/rinetd-rinetd.Tpo -c -o rinetd-rinetd.o `test -f 'rinetd.c' || echo './'`rinetd.c
# gcc -DHAVE_CONFIG_H -I.    -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2 -MT rinetd-match.o -MD -MP -MF .deps/rinetd-match.Tpo -c -o rinetd-match.o `test -f 'match.c' || echo './'`match.c
# rm -f rinetd
# gcc -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2   -o rinetd rinetd-rinetd.o rinetd-match.o  

gcc -DHAVE_CONFIG_H -I.  -I/home/vagrant/lkl/linux/tools/lkl/include  -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fno-strict-aliasing -fPIC -pthread -Wwrite-strings -I. -g -O2 -fPIC -DCONFIG_AUTO_LKL_POSIX_HOST -MT rinetd-rinetd.o -MD -MP -MF .deps/rinetd-rinetd.Tpo -c -o rinetd-rinetd.o `test -f 'rinetd.c' || echo './'`rinetd.c
gcc -DHAVE_CONFIG_H -I.    -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2 -MT rinetd-match.o -MD -MP -MF .deps/rinetd-match.Tpo -c -o rinetd-match.o `test -f 'match.c' || echo './'`match.c
gcc -DHAVE_CONFIG_H -I.    -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -g -O2 -MT rinetd-thpool.o -MD -MP -MF .deps/rinetd-thpool.Tpo -c -o rinetd-thpool.o `test -f 'thpool.c' || echo './'`thpool.c
rm -f rinetd
ld -r -o rinetd-rinetd-in.o rinetd-rinetd.o
gcc -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I. -I/home/vagrant/lkl/linux/tools/lkl/include  -g -O2   -o rinetd rinetd-rinetd-in.o rinetd-match.o rinetd-thpool.o /home/vagrant/lkl/linux/tools/lkl/liblkl.a -lrt -lpthread
