# Don't edit Makefile!  Use conf-* for configuration.

SHELL=/bin/sh

default: it

clean:
	rm -f alloc.o alloc_re.o buffer.o buffer_0.o buffer_1.o buffer_2.o \
	buffer_copy.o buffer_get.o buffer_put.o buffer_read.o buffer_write.o \
	byte_chr.o byte_copy.o byte_cr.o byte_diff.o byte_zero.o case_diffb.o \
	case_diffs.o ccperl cdb.o cdb_hash.o cdb_make.o chkshsgr chkshsgr.o \
	choose coe.o compile dns_dfd.o dns_domain.o dns_dtda.o dns_ip.o \
	dns_ipq.o dns_name.o dns_nd.o dns_packet.o dns_random.o dns_rcip.o \
	dns_rcrw.o dns_resolve.o dns_sortip.o dns_transmit.o env.o error.o \
	error_str.o fd_copy.o fd_move.o fd_shutdown.o fmt_ulong.o hasflock.h \
	hassgact.h hassgprm.h hasshsgr.h haswaitp.h iopause.h iopause.o \
	iopause_proxy.o ip4_fmt.o ip4_scan.o it load lock_ex.o lock_un.o \
	makeinclude makelib makescrip ndelay_off.o ndelay_on.o open_append.o \
	open_read.o openreadclose.o perlembed.lib prot.o readclose.o \
	remoteinfo.o rules.o scan_uint.o scan_ulong.o seek_set.o select.h \
	sgetopt.o sig.o sig_block.o sig_catch.o sig_pause.o socket.lib \
	socket_accept.o socket_bind.o socket_conn.o socket_delay.o \
	socket_listen.o socket_local.o socket_opts.o socket_tcp.o socket_udp.o \
	str_chr.o str_diff.o str_len.o str_start.o stralloc_cat.o \
	stralloc_catb.o stralloc_cats.o stralloc_copy.o stralloc_eady.o \
	stralloc_opyb.o stralloc_opys.o stralloc_pend.o strerr.o strerr_die.o \
	strerr_sys.o subgetopt.o sysdeps systype tai_pack.o taia_add.o \
	taia_approx.o taia_frac.o taia_less.o taia_now.o taia_pack.o taia_sub.o \
	taia_uint.o tcphandle.o tcpperl tcpperl.o tcpprint tcpprint.o \
	timeoutconn.o uint16_pack.o uint16_unpack.o uint32.h uint32_pack.o \
	uint32_unpack.o uint64.h unix.a wait_nohang.o

alloc.o: compile alloc.c alloc.h error.h
	./compile alloc.c

alloc_re.o: compile alloc_re.c alloc.h byte.h
	./compile alloc_re.c

buffer.o: compile buffer.c buffer.h
	./compile buffer.c

buffer_0.o: compile buffer_0.c buffer.h
	./compile buffer_0.c

buffer_1.o: compile buffer_1.c buffer.h
	./compile buffer_1.c

buffer_2.o: compile buffer_2.c buffer.h
	./compile buffer_2.c

buffer_copy.o: compile buffer_copy.c buffer.h
	./compile buffer_copy.c

buffer_get.o: compile buffer_get.c buffer.h byte.h error.h
	./compile buffer_get.c

buffer_put.o: compile buffer_put.c buffer.h str.h byte.h error.h
	./compile buffer_put.c

buffer_read.o: compile buffer_read.c buffer.h
	./compile buffer_read.c

buffer_write.o: compile buffer_write.c buffer.h
	./compile buffer_write.c

byte_chr.o: compile byte_chr.c byte.h
	./compile byte_chr.c

byte_copy.o: compile byte_copy.c byte.h
	./compile byte_copy.c

byte_cr.o: compile byte_cr.c byte.h
	./compile byte_cr.c

byte_diff.o: compile byte_diff.c byte.h
	./compile byte_diff.c

byte_zero.o: compile byte_zero.c byte.h
	./compile byte_zero.c

case_diffb.o: compile case_diffb.c case.h
	./compile case_diffb.c

case_diffs.o: compile case_diffs.c case.h
	./compile case_diffs.c

ccperl: conf-ccperl conf-perl print-ccperl.sh
	rm -f ccperl
	sh print-ccperl.sh > ccperl

cdb.o: compile cdb.c error.h seek.h byte.h cdb.h uint32.h
	./compile cdb.c

cdb_hash.o: compile cdb_hash.c cdb.h uint32.h
	./compile cdb_hash.c

cdb_make.o: compile cdb_make.c seek.h error.h alloc.h cdb.h cdb_make.h \
uint32.h buffer.h uint32.h
	./compile cdb_make.c

chkshsgr: load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: compile chkshsgr.c exit.h
	./compile chkshsgr.c

choose: makeinclude makescrip warn-auto.sh choose.sh
	rm -f choose
	./makeinclude code warn-auto.sh choose.sh \
	| ./makescrip choose choose choose.tmp \
	> choose
	chmod 755 choose

coe.o: compile coe.c coe.h
	./compile coe.c

compile: conf-cc print-cc.sh systype warn-auto.sh
	rm -f compile
	sh print-cc.sh > compile
	chmod 755 compile

dns_dfd.o: compile dns_dfd.c error.h alloc.h byte.h dns.h stralloc.h \
iopause.h taia.h gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_dfd.c

dns_domain.o: compile dns_domain.c error.h alloc.h case.h byte.h dns.h \
stralloc.h iopause.h taia.h gen_alloc.h taia.h tai.h tai.h uint64.h \
uint64.h
	./compile dns_domain.c

dns_dtda.o: compile dns_dtda.c stralloc.h dns.h gen_alloc.h stralloc.h \
iopause.h taia.h gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_dtda.c

dns_ip.o: compile dns_ip.c stralloc.h uint16.h byte.h dns.h gen_alloc.h \
stralloc.h iopause.h taia.h gen_alloc.h taia.h tai.h tai.h uint64.h \
uint64.h
	./compile dns_ip.c

dns_ipq.o: compile dns_ipq.c stralloc.h case.h byte.h str.h dns.h \
gen_alloc.h stralloc.h iopause.h taia.h gen_alloc.h taia.h tai.h tai.h \
uint64.h uint64.h
	./compile dns_ipq.c

dns_name.o: compile dns_name.c stralloc.h uint16.h byte.h dns.h \
gen_alloc.h stralloc.h iopause.h taia.h gen_alloc.h taia.h tai.h tai.h \
uint64.h uint64.h
	./compile dns_name.c

dns_nd.o: compile dns_nd.c byte.h fmt.h dns.h stralloc.h iopause.h taia.h \
gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_nd.c

dns_packet.o: compile dns_packet.c error.h dns.h stralloc.h iopause.h \
taia.h gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_packet.c

dns_random.o: compile dns_random.c dns.h taia.h uint32.h stralloc.h \
iopause.h taia.h tai.h gen_alloc.h taia.h tai.h uint64.h tai.h uint64.h \
uint64.h
	./compile dns_random.c

dns_rcip.o: compile dns_rcip.c taia.h openreadclose.h byte.h ip4.h env.h \
dns.h tai.h stralloc.h stralloc.h iopause.h taia.h uint64.h gen_alloc.h \
gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_rcip.c

dns_rcrw.o: compile dns_rcrw.c taia.h env.h byte.h str.h openreadclose.h \
dns.h tai.h stralloc.h stralloc.h iopause.h taia.h uint64.h gen_alloc.h \
gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_rcrw.c

dns_resolve.o: compile dns_resolve.c iopause.h taia.h byte.h dns.h taia.h \
tai.h stralloc.h iopause.h taia.h tai.h uint64.h gen_alloc.h taia.h tai.h \
uint64.h tai.h uint64.h uint64.h
	./compile dns_resolve.c

dns_sortip.o: compile dns_sortip.c byte.h dns.h stralloc.h iopause.h \
taia.h gen_alloc.h taia.h tai.h tai.h uint64.h uint64.h
	./compile dns_sortip.c

dns_transmit.o: compile dns_transmit.c socket.h alloc.h error.h byte.h \
uint16.h dns.h uint16.h stralloc.h iopause.h taia.h gen_alloc.h taia.h \
tai.h tai.h uint64.h uint64.h
	./compile dns_transmit.c

env.o: compile env.c str.h env.h
	./compile env.c

error.o: compile error.c error.h
	./compile error.c

error_str.o: compile error_str.c error.h
	./compile error_str.c

fd_copy.o: compile fd_copy.c fd.h
	./compile fd_copy.c

fd_move.o: compile fd_move.c fd.h
	./compile fd_move.c

fd_shutdown.o: compile fd_shutdown.c fd.h error.h
	./compile fd_shutdown.c

fmt_ulong.o: compile fmt_ulong.c fmt.h
	./compile fmt_ulong.c

hasflock.h: choose compile load tryflock.c hasflock.h1 hasflock.h2
	./choose cl tryflock hasflock.h1 hasflock.h2 > hasflock.h

hassgact.h: choose compile trysgact.c hassgact.h1 hassgact.h2
	./choose cl trysgact hassgact.h1 hassgact.h2 > hassgact.h

hassgprm.h: choose compile trysgprm.c hassgprm.h1 hassgprm.h2
	./choose cl trysgprm hassgprm.h1 hassgprm.h2 > hassgprm.h

hasshsgr.h: choose compile tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr \
warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

haswaitp.h: choose compile load trywaitp.c haswaitp.h1 haswaitp.h2
	./choose cl trywaitp haswaitp.h1 haswaitp.h2 >haswaitp.h

iopause.h: choose compile load trypoll.c iopause.h1 iopause.h2
	./choose clr trypoll iopause.h1 iopause.h2 >iopause.h

iopause.o: compile iopause.c taia.h select.h iopause.h tai.h taia.h \
uint64.h tai.h uint64.h
	./compile iopause.c

iopause_proxy.o: compile iopause_proxy.c iopause.h buffer.h fd.h error.h \
sig.h strerr.h taia.h tai.h uint64.h
	./compile iopause_proxy.c

ip4_fmt.o: compile ip4_fmt.c fmt.h ip4.h
	./compile ip4_fmt.c

ip4_scan.o: compile ip4_scan.c scan.h ip4.h
	./compile ip4_scan.c

it: sysdeps tcpprint tcpperl

load: conf-ld print-ld.sh systype warn-auto.sh
	rm -f load
	sh print-ld.sh > load
	chmod 755 load

lock_ex.o: compile lock_ex.c hasflock.h lock.h
	./compile lock_ex.c

lock_un.o: compile lock_un.c hasflock.h lock.h
	./compile lock_un.c

makeinclude: makeinclude.sh warn-auto.sh
	rm -f makeinclude
	cat warn-auto.sh makeinclude.sh > makeinclude
	chmod 755 makeinclude

makelib: print-ar.sh systype warn-auto.sh
	rm -f makelib
	sh print-ar.sh > makelib
	chmod 755 makelib

makescrip: warn-auto.sh print-makescrip.sh conf-scrip home
	rm -f makescrip
	sh print-makescrip.sh < conf-scrip > makescrip
	chmod 755 makescrip

ndelay_off.o: compile ndelay_off.c ndelay.h
	./compile ndelay_off.c

ndelay_on.o: compile ndelay_on.c ndelay.h
	./compile ndelay_on.c

open_append.o: compile open_append.c open.h
	./compile open_append.c

open_read.o: compile open_read.c open.h
	./compile open_read.c

openreadclose.o: compile openreadclose.c error.h open.h readclose.h \
openreadclose.h stralloc.h stralloc.h gen_alloc.h gen_alloc.h
	./compile openreadclose.c

perlembed.lib: conf-perl conf-ldperl print-perlembed.sh
	rm -f perlembed.lib
	sh print-ldperl.sh > perlembed.lib

prot.o: compile prot.c hasshsgr.h prot.h
	./compile prot.c

readclose.o: compile readclose.c error.h readclose.h stralloc.h \
gen_alloc.h
	./compile readclose.c

remoteinfo.o: compile remoteinfo.c fmt.h buffer.h socket.h error.h \
iopause.h timeoutconn.h remoteinfo.h uint16.h taia.h uint16.h stralloc.h \
uint16.h tai.h gen_alloc.h uint64.h
	./compile remoteinfo.c

rules.o: compile rules.c alloc.h stralloc.h open.h cdb.h rules.h \
gen_alloc.h uint32.h stralloc.h gen_alloc.h
	./compile rules.c

scan_uint.o: compile scan_uint.c scan.h
	./compile scan_uint.c

scan_ulong.o: compile scan_ulong.c scan.h
	./compile scan_ulong.c

seek_set.o: compile seek_set.c seek.h
	./compile seek_set.c

select.h: choose compile trysysel.c select.h1 select.h2
	./choose c trysysel select.h1 select.h2 > select.h

sgetopt.o: compile sgetopt.c buffer.h sgetopt.h subgetopt.h subgetopt.h
	./compile sgetopt.c

sig.o: compile sig.c sig.h
	./compile sig.c

sig_block.o: compile sig_block.c sig.h hassgprm.h
	./compile sig_block.c

sig_catch.o: compile sig_catch.c sig.h hassgact.h
	./compile sig_catch.c

sig_pause.o: compile sig_pause.c sig.h hassgprm.h
	./compile sig_pause.c

socket.lib: trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

socket_accept.o: compile socket_accept.c byte.h socket.h uint16.h
	./compile socket_accept.c

socket_bind.o: compile socket_bind.c byte.h socket.h uint16.h
	./compile socket_bind.c

socket_conn.o: compile socket_conn.c byte.h socket.h uint16.h
	./compile socket_conn.c

socket_delay.o: compile socket_delay.c socket.h uint16.h
	./compile socket_delay.c

socket_listen.o: compile socket_listen.c socket.h uint16.h
	./compile socket_listen.c

socket_local.o: compile socket_local.c byte.h socket.h uint16.h
	./compile socket_local.c

socket_opts.o: compile socket_opts.c socket.h uint16.h
	./compile socket_opts.c

socket_tcp.o: compile socket_tcp.c ndelay.h socket.h uint16.h
	./compile socket_tcp.c

socket_udp.o: compile socket_udp.c ndelay.h socket.h uint16.h
	./compile socket_udp.c

str_chr.o: compile str_chr.c str.h
	./compile str_chr.c

str_diff.o: compile str_diff.c str.h
	./compile str_diff.c

str_len.o: compile str_len.c str.h
	./compile str_len.c

str_start.o: compile str_start.c str.h
	./compile str_start.c

stralloc_cat.o: compile stralloc_cat.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_cat.c

stralloc_catb.o: compile stralloc_catb.c stralloc.h byte.h gen_alloc.h
	./compile stralloc_catb.c

stralloc_cats.o: compile stralloc_cats.c byte.h str.h stralloc.h \
gen_alloc.h
	./compile stralloc_cats.c

stralloc_copy.o: compile stralloc_copy.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_copy.c

stralloc_eady.o: compile stralloc_eady.c alloc.h stralloc.h \
gen_allocdefs.h gen_alloc.h
	./compile stralloc_eady.c

stralloc_opyb.o: compile stralloc_opyb.c stralloc.h byte.h gen_alloc.h
	./compile stralloc_opyb.c

stralloc_opys.o: compile stralloc_opys.c byte.h str.h stralloc.h \
gen_alloc.h
	./compile stralloc_opys.c

stralloc_pend.o: compile stralloc_pend.c alloc.h stralloc.h \
gen_allocdefs.h gen_alloc.h
	./compile stralloc_pend.c

strerr.o: compile strerr.c stralloc.h strerr.h gen_alloc.h
	./compile strerr.c

strerr_die.o: compile strerr_die.c buffer.h exit.h strerr.h
	./compile strerr_die.c

strerr_sys.o: compile strerr_sys.c error.h strerr.h
	./compile strerr_sys.c

subgetopt.o: compile subgetopt.c subgetopt.h
	./compile subgetopt.c

sysdeps: systype compile load
	rm -f sysdeps
	cat systype compile load >> sysdeps
	grep sysdep *.h 2>/dev/null >> sysdeps || :

systype: find-systype.sh trycpp.c x86cpuid.c
	sh find-systype.sh > systype

tai_pack.o: compile tai_pack.c tai.h uint64.h
	./compile tai_pack.c

taia_add.o: compile taia_add.c taia.h tai.h uint64.h
	./compile taia_add.c

taia_approx.o: compile taia_approx.c taia.h tai.h uint64.h
	./compile taia_approx.c

taia_frac.o: compile taia_frac.c taia.h tai.h uint64.h
	./compile taia_frac.c

taia_less.o: compile taia_less.c taia.h tai.h uint64.h
	./compile taia_less.c

taia_now.o: compile taia_now.c taia.h tai.h uint64.h
	./compile taia_now.c

taia_pack.o: compile taia_pack.c taia.h tai.h uint64.h
	./compile taia_pack.c

taia_sub.o: compile taia_sub.c taia.h tai.h uint64.h
	./compile taia_sub.c

taia_uint.o: compile taia_uint.c taia.h tai.h uint64.h
	./compile taia_uint.c

tcphandle.o: compile tcphandle.c uint16.h str.h byte.h fmt.h scan.h ip4.h \
fd.h exit.h env.h prot.h open.h wait.h stralloc.h alloc.h buffer.h \
error.h strerr.h sgetopt.h socket.h ndelay.h remoteinfo.h rules.h sig.h \
dns.h iopause.h coe.h lock.h gen_alloc.h subgetopt.h uint16.h stralloc.h \
uint16.h stralloc.h stralloc.h iopause.h taia.h taia.h gen_alloc.h \
gen_alloc.h gen_alloc.h taia.h tai.h tai.h tai.h uint64.h uint64.h \
uint64.h
	./compile tcphandle.c

tcpperl: load tcpperl.o tcphandle.o unix.a socket.lib perlembed.lib
	./load tcpperl tcphandle.o unix.a  `cat socket.lib` `cat perlembed.lib`

tcpperl.o: compile ccperl tcpperl.c strerr.h stralloc.h str.h gen_alloc.h
	./compile `cat ccperl` tcpperl.c

tcpprint: load tcpprint.o tcphandle.o unix.a socket.lib
	./load tcpprint tcphandle.o unix.a  `cat socket.lib`

tcpprint.o: compile tcpprint.c buffer.h env.h
	./compile tcpprint.c

timeoutconn.o: compile timeoutconn.c ndelay.h socket.h iopause.h error.h \
timeoutconn.h uint16.h taia.h uint16.h tai.h uint64.h
	./compile timeoutconn.c

uint16_pack.o: compile uint16_pack.c uint16.h
	./compile uint16_pack.c

uint16_unpack.o: compile uint16_unpack.c uint16.h
	./compile uint16_unpack.c

uint32.h: choose compile load tryulong32.c uint32.h1 uint32.h2
	./choose clr tryulong32 uint32.h1 uint32.h2 >uint32.h

uint32_pack.o: compile uint32_pack.c uint32.h
	./compile uint32_pack.c

uint32_unpack.o: compile uint32_unpack.c uint32.h
	./compile uint32_unpack.c

uint64.h: choose compile load tryulong64.c uint64.h1 uint64.h2
	./choose clr tryulong64 uint64.h1 uint64.h2 >uint64.h

unix.a: makelib alloc.o alloc_re.o buffer_0.o buffer_1.o buffer_2.o \
buffer_get.o buffer_put.o buffer_copy.o buffer_read.o buffer_write.o \
buffer.o stralloc_cat.o stralloc_catb.o stralloc_copy.o stralloc_opyb.o \
stralloc_opys.o stralloc_cats.o stralloc_pend.o stralloc_eady.o env.o \
byte_zero.o byte_diff.o byte_chr.o byte_cr.o byte_copy.o uint16_pack.o \
uint16_unpack.o uint32_pack.o uint32_unpack.o fmt_ulong.o scan_uint.o \
scan_ulong.o str_diff.o str_len.o str_start.o str_chr.o case_diffs.o \
case_diffb.o open_read.o open_append.o fd_move.o fd_copy.o fd_shutdown.o \
strerr.o strerr_die.o strerr_sys.o sig.o sig_catch.o sig_block.o \
sig_pause.o error.o error_str.o ndelay_off.o ndelay_on.o socket_tcp.o \
socket_accept.o socket_bind.o socket_local.o socket_listen.o \
socket_opts.o socket_delay.o socket_conn.o socket_udp.o subgetopt.o \
sgetopt.o ip4_fmt.o ip4_scan.o dns_name.o dns_ip.o dns_ipq.o \
dns_resolve.o dns_packet.o dns_domain.o dns_packet.o dns_transmit.o \
dns_rcrw.o dns_random.o dns_sortip.o dns_rcip.o dns_dfd.o dns_nd.o \
dns_rcip.o dns_dtda.o taia_add.o taia_sub.o taia_approx.o taia_frac.o \
taia_now.o taia_less.o taia_uint.o taia_pack.o tai_pack.o iopause.o \
iopause_proxy.o openreadclose.o readclose.o remoteinfo.o timeoutconn.o \
seek_set.o cdb.o cdb_hash.o cdb_make.o prot.o rules.o coe.o wait_nohang.o \
lock_ex.o lock_un.o
	./makelib unix.a alloc.o alloc_re.o buffer_0.o buffer_1.o buffer_2.o \
	buffer_get.o buffer_put.o buffer_copy.o buffer_read.o buffer_write.o \
	buffer.o stralloc_cat.o stralloc_catb.o stralloc_copy.o stralloc_opyb.o \
	stralloc_opys.o stralloc_cats.o stralloc_pend.o stralloc_eady.o env.o \
	byte_zero.o byte_diff.o byte_chr.o byte_cr.o byte_copy.o uint16_pack.o \
	uint16_unpack.o uint32_pack.o uint32_unpack.o fmt_ulong.o scan_uint.o \
	scan_ulong.o str_diff.o str_len.o str_start.o str_chr.o case_diffs.o \
	case_diffb.o open_read.o open_append.o fd_move.o fd_copy.o fd_shutdown.o \
	strerr.o strerr_die.o strerr_sys.o sig.o sig_catch.o sig_block.o \
	sig_pause.o error.o error_str.o ndelay_off.o ndelay_on.o socket_tcp.o \
	socket_accept.o socket_bind.o socket_local.o socket_listen.o \
	socket_opts.o socket_delay.o socket_conn.o socket_udp.o subgetopt.o \
	sgetopt.o ip4_fmt.o ip4_scan.o dns_name.o dns_ip.o dns_ipq.o \
	dns_resolve.o dns_packet.o dns_domain.o dns_packet.o dns_transmit.o \
	dns_rcrw.o dns_random.o dns_sortip.o dns_rcip.o dns_dfd.o dns_nd.o \
	dns_rcip.o dns_dtda.o taia_add.o taia_sub.o taia_approx.o taia_frac.o \
	taia_now.o taia_less.o taia_uint.o taia_pack.o tai_pack.o iopause.o \
	iopause_proxy.o openreadclose.o readclose.o remoteinfo.o timeoutconn.o \
	seek_set.o cdb.o cdb_hash.o cdb_make.o prot.o rules.o coe.o \
	wait_nohang.o lock_ex.o lock_un.o

wait_nohang.o: compile wait_nohang.c haswaitp.h
	./compile wait_nohang.c
