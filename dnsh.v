module main

import os
import time
import rand

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

fn C.gethostbyname(name &u8) voidptr
fn C.socket(domain int, @type int, protocol int) int
fn C.close(fd int) int
fn C.connect(fd int, addr voidptr, addrlen u32) int
fn C.send(fd int, buf voidptr, len usize, flags int) isize
fn C.recv(fd int, buf voidptr, len usize, flags int) isize
fn C.recvfrom(fd int, buf voidptr, len usize, flags int, src_addr voidptr, addrlen voidptr) isize
fn C.sendto(fd int, buf voidptr, len usize, flags int, dest_addr voidptr, addrlen u32) isize
fn C.setsockopt(fd int, level int, optname int, optval voidptr, optlen u32) int
fn C.htons(v u16) u16
fn C.inet_pton(af int, src &u8, dst voidptr) int
fn C.getsockname(fd int, addr voidptr, addrlen voidptr) int

struct C.sockaddr_in {
mut:
	sin_family u16
	sin_port   u16
	sin_addr   C.in_addr
}

struct C.in_addr {
mut:
	s_addr u32
}

struct SockTimeout {
mut:
	sec  i64
	usec i64
}

__global g_dns = ''
__global g_workers = 4

fn char_idx(ch u8) int {
	if ch == ` ` { return 0 }
	return int(ch - `a`) + 1
}

fn huffman_encode(msg string) ([]u8, string) {
	codes :=[u32(0), 5, 60, 25, 22, 1, 56, 57, 21, 7, 125, 124, 23, 26, 8, 6, 59, 254, 20, 9, 4, 24, 61, 27, 126, 58, 255]
	lens :=[u8(3), 4, 6, 5, 5, 3, 6, 6, 5, 4, 7, 7, 5, 5, 4, 4, 6, 8, 5, 4, 4, 5, 6, 5, 7, 6, 8]

	mut filtered :=[]u8{}
	for ch in msg.bytes() {
		mut c := ch
		if c >= `A` && c <= `Z` { c += 32 }
		if (c >= `a` && c <= `z`) || c == ` ` { filtered << c }
	}

	mut bits :=[]u8{}
	for c in filtered {
		idx := char_idx(c)
		code := codes[idx]
		length := int(lens[idx])
		for b in 0 .. length {
			bits << u8((code >> u32(length - 1 - b)) & 1)
		}
	}

	mut result :=[]u8{}
	result << u8(filtered.len)
	mut i := 0
	for i < bits.len {
		mut bv := u8(0)
		for b in 0 .. 8 {
			bv = bv << 1
			if i + b < bits.len { bv |= bits[i + b] }
		}
		result << bv
		i += 8
	}
	return result, filtered.bytestr()
}

fn huffman_decode(data[]u8) string {
	if data.len < 2 { return '' }
	nchars := int(data[0])
	syms :=[u8(` `), `e`, `t`, `a`, `o`, `i`, `n`, `s`, `r`, `h`, `d`, `l`, `u`, `c`, `m`, `w`, `f`, `g`, `y`, `p`, `b`, `v`, `k`, `j`, `x`, `q`, `z`]
	fc :=[0, 0, 0, 0, 4, 20, 56, 124, 254]
	fo :=[0, 0, 0, 0, 2, 8, 16, 22, 25]
	cn :=[0, 0, 0, 2, 6, 8, 6, 3, 2]

	mut bits :=[]u8{}
	for i in 1 .. data.len {
		for b in 0 .. 8 {
			bits << (data[i] >> u8(7 - b)) & 1
		}
	}

	mut result :=[]u8{}
	mut pos := 0
	for _ in 0 .. nchars {
		mut code := 0
		mut found := false
		for l in 1 .. 9 {
			if pos >= bits.len { break }
			code = (code << 1) | int(bits[pos])
			pos++
			if l >= 3 && code >= fc[l] && code - fc[l] < cn[l] {
				result << syms[fo[l] + code - fc[l]]
				found = true
				break
			}
		}
		if !found { break }
	}
	return result.bytestr()
}

fn build_dns_query(host string, tx_id u16)[]u8 {
	mut pkt :=[]u8{cap: 128}
	pkt << u8((tx_id >> 8) & 0xFF)
	pkt << u8(tx_id & 0xFF)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	for label in host.split('.') {
		pkt << u8(label.len)
		pkt << label.bytes()
	}
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x01)
	return pkt
}

fn ip_checksum(buf[]u8) u16 {
	mut sum := u32(0)
	mut i := 0
	for i + 1 < buf.len {
		sum += (u32(buf[i]) << 8) | u32(buf[i + 1])
		i += 2
	}
	if i < buf.len { sum += u32(buf[i]) << 8 }
	for (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
	mut ans := u16(~sum & 0xffff)
	if ans == 0 { ans = 0xffff }
	return ans
}

fn udp_checksum(src_ip[]u8, dst_ip []u8, udp_packet[]u8) u16 {
	mut sum := u32(0)
	sum += (u32(src_ip[0]) << 8) | u32(src_ip[1])
	sum += (u32(src_ip[2]) << 8) | u32(src_ip[3])
	sum += (u32(dst_ip[0]) << 8) | u32(dst_ip[1])
	sum += (u32(dst_ip[2]) << 8) | u32(dst_ip[3])
	sum += 0x0011 
	sum += u32(udp_packet.len)
	mut i := 0
	for i + 1 < udp_packet.len {
		sum += (u32(udp_packet[i]) << 8) | u32(udp_packet[i + 1])
		i += 2
	}
	if i < udp_packet.len { sum += u32(udp_packet[i]) << 8 }
	for (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16) }
	mut ans := u16(~sum & 0xffff)
	if ans == 0 { ans = 0xffff }
	return ans
}

fn build_raw_udp(src_ip []u8, dst_ip[]u8, src_port u16, dst_port u16, ttl u8, payload []u8)[]u8 {
	udp_len := 8 + payload.len
	total_len := 20 + udp_len
	mut pkt := []u8{len: total_len}

	pkt[0] = 0x45
	pkt[1] = 0x00
	pkt[2] = u8((total_len >> 8) & 0xff)
	pkt[3] = u8(total_len & 0xff)
	pkt[4] = 0xDE
	pkt[5] = 0xAD
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = ttl
	pkt[9] = 17 

	for i in 0 .. 4 {
		pkt[12 + i] = src_ip[i]
		pkt[16 + i] = dst_ip[i]
	}

	ip_ck := ip_checksum(pkt[..20])
	pkt[10] = u8((ip_ck >> 8) & 0xff)
	pkt[11] = u8(ip_ck & 0xff)

	pkt[20] = u8((src_port >> 8) & 0xff)
	pkt[21] = u8(src_port & 0xff)
	pkt[22] = u8((dst_port >> 8) & 0xff)
	pkt[23] = u8(dst_port & 0xff)
	pkt[24] = u8((udp_len >> 8) & 0xff)
	pkt[25] = u8(udp_len & 0xff)
	pkt[26] = 0
	pkt[27] = 0

	for i in 0 .. payload.len { pkt[28 + i] = payload[i] }

	udp_ck := udp_checksum(src_ip, dst_ip, pkt[20..])
	pkt[26] = u8((udp_ck >> 8) & 0xff)
	pkt[27] = u8(udp_ck & 0xff)

	return pkt
}

fn send_raw_packet(dst_ip[]u8, dst_port u16, pkt[]u8) bool {
	$if !windows {
		raw_fd := C.socket(C.AF_INET, C.SOCK_RAW, 255)
		if raw_fd < 0 { return false }
		
		mut one := int(1)
		C.setsockopt(raw_fd, C.IPPROTO_IP, C.IP_HDRINCL, &one, sizeof(one))
		
		mut dest := [16]u8{}
		dest[0] = 2 
		dest[2] = u8(dst_port >> 8)
		dest[3] = u8(dst_port & 0xFF)
		dest[4] = dst_ip[0]
		dest[5] = dst_ip[1]
		dest[6] = dst_ip[2]
		dest[7] = dst_ip[3]
		
		C.sendto(raw_fd, voidptr(pkt.data), pkt.len, 0, voidptr(&dest), u32(16))
		C.close(raw_fd)
		return true
	}
	return false
}

fn get_local_ip(dns_ip string)[]u8 {
	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	mut sa := C.sockaddr_in{}
	sa.sin_family = u16(C.AF_INET)
	sa.sin_port = C.htons(53)
	C.inet_pton(C.AF_INET, dns_ip.str, &sa.sin_addr)
	C.connect(fd, &sa, sizeof(sa))
	
	mut local_sa := C.sockaddr_in{}
	mut sa_len := u32(sizeof(local_sa))
	C.getsockname(fd, &local_sa, &sa_len)
	C.close(fd)
	
	ptr := unsafe { &u8(&local_sa.sin_addr.s_addr) }
	return [unsafe{ptr[0]}, unsafe{ptr[1]}, unsafe{ptr[2]}, unsafe{ptr[3]}]
}

fn resolve_raw(host string) !i64 {
	$if windows { return error('raw sockets not supported on windows') }
	
	mut dst_ip :=[]u8{len: 4}
	mut ip_parts := g_dns.split('.')
	if ip_parts.len == 4 {
		for i in 0 .. 4 { dst_ip[i] = u8(ip_parts[i].int()) }
	} else { return error('invalid dns ip') }

	src_ip := get_local_ip(g_dns)
	src_port := u16(rand.intn(50000) or { 10000 } + 10000)
	tx_id := u16(rand.intn(65535) or { 0 })

	dns_payload := build_dns_query(host, tx_id)
	raw_pkt := build_raw_udp(src_ip, dst_ip, src_port, 53, 64, dns_payload)

	rx_fd := C.socket(C.AF_INET, C.SOCK_RAW, 17) // IPPROTO_UDP
	if rx_fd < 0 { return error('requires root for raw socket') }
	
	tv := SockTimeout{sec: 2, usec: 0}
	C.setsockopt(rx_fd, C.SOL_SOCKET, C.SO_RCVTIMEO, &tv, sizeof(tv))

	sw := time.new_stopwatch()
	send_raw_packet(dst_ip, 53, raw_pkt)
	
	mut buf :=[]u8{len: 2048}
	for {
		n := C.recvfrom(rx_fd, buf.data, 2048, 0, 0, 0)
		if n < 0 { break }
		
		if n > 28 {
			ip_hlen := (buf[0] & 0x0F) * 4
			if buf[9] == 17 { 
				src_port_rx := (u16(buf[ip_hlen]) << 8) | u16(buf[ip_hlen+1])
				dst_port_rx := (u16(buf[ip_hlen+2]) << 8) | u16(buf[ip_hlen+3])
				
				if src_port_rx == 53 && dst_port_rx == src_port {
					elapsed := sw.elapsed().microseconds()
					C.close(rx_fd)
					return elapsed
				}
			}
		}
		if sw.elapsed().milliseconds() > 2000 { break }
	}
	
	C.close(rx_fd)
	return error('timeout')
}

fn resolve(host string) !i64 {
	if g_dns.len > 0 { return resolve_raw(host) }
	sw := time.new_stopwatch()
	_ := C.gethostbyname(host.str)
	elapsed := sw.elapsed().microseconds()
	if elapsed > 5000000 { return error('timeout') }
	return elapsed
}

fn resolve_safe(host string) i64 {
	for attempt in 0 .. 3 {
		t := resolve(host) or {
			time.sleep((100 + attempt * 200) * time.millisecond)
			continue
		}
		return t
	}
	return -1
}

@[noreturn]
fn die(s string) {
	eprintln('[!] ${s}')
	exit(1)
}

fn send_byte(base string, byte_idx int, ch u8) {
	for bit in 0 .. 8 {
		idx := byte_idx * 8 + bit
		b := u8((ch >> (7 - bit)) & 1)
		if b == 0 {
			for _ in 0 .. 5 {
				resolve('${idx}.${base}') or {}
				resolve('v${idx}.${base}') or {}
				resolve('w${idx}.${base}') or {}
			}
		}
	}
}

fn send_mode(base string, msg string) {
	resolve('c0.${base}') or {}
	time.sleep(50 * time.millisecond)
	resolve('c0.${base}') or {}

	data, filtered := huffman_encode(msg)

	println('[tx] "${msg}" -> "${filtered}" (${filtered.len} chars)')
	println('[tx] ${data.len} wire bytes (huffman)')
	if g_dns == "" { println('[tx] receiver cmd:  dnsh rec ${base} ${data.len}') }
	else { println('[tx] receiver cmd:  sudo ./dnsh --dns ${g_dns} rec ${base} ${data.len}') }
	println('[tx] sending with ${g_workers} workers...')

	mut pos := 0
	for pos < data.len {
		mut end := pos + g_workers
		if end > data.len { end = data.len }
		mut threads :=[]thread{}
		for i in pos .. end {
			threads << spawn send_byte(base, i, data[i])
		}
		threads.wait()
		time.sleep(50 * time.millisecond)
		pos = end
	}

	mut zeros := 0
	for ch in data {
		for bit in 0 .. 8 {
			if ((ch >> (7 - bit)) & 1) == 0 { zeros++ }
		}
	}

	println('[tx] cached ${zeros} subdomains')
	println('[tx] keepalive running... (ctrl+c to stop)\n')
	
	mut round := 0
	for {
		round++
		mut refreshed := 0
		for i in 0 .. data.len {
			ch := data[i]
			for bit in 0 .. 8 {
				idx := i * 8 + bit
				if ((ch >> (7 - bit)) & 1) == 0 {
					resolve('${idx}.${base}') or {}
					time.sleep(20 * time.millisecond)
					resolve('v${idx}.${base}') or {}
					time.sleep(20 * time.millisecond)
					resolve('w${idx}.${base}') or {}
					time.sleep(20 * time.millisecond)
					refreshed++
				}
			}
		}
		println('[keepalive #${round}] ${refreshed} entries refreshed')
		time.sleep(5 * time.second)
	}
}

fn rec_mode(base string, nbytes int) {
	println('[rx] reading ${nbytes} wire bytes (huffman)...\n')
	println('[rx] calibrating using Raw Sockets...')

	mut fast_arr := []i64{}
	mut slow_arr :=[]i64{}

	for _ in 0 .. 5 {
		f := resolve_safe('c0.${base}')
		if f >= 0 { fast_arr << f }
		time.sleep(50 * time.millisecond)
	}
	for _ in 0 .. 5 {
		s := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
		if s >= 0 { slow_arr << s }
		time.sleep(50 * time.millisecond)
	}

	if fast_arr.len < 3 || slow_arr.len < 3 { die('calibration failed') }

	fast_arr.sort()
	slow_arr.sort()
	fast_med := fast_arr[fast_arr.len / 2]
	slow_med := slow_arr[slow_arr.len / 2]
	gap := slow_med - fast_med

	if gap < 1000 {
		die('gap ${gap}µs too small (fast:${fast_med}µs slow:${slow_med}µs) - sender running?')
	}

	mut thr := ((fast_med + slow_med + gap) / 3) - 500
	if thr < 1000 { thr = 1000 }

	println('[rx] fast:${fast_med}µs slow:${slow_med}µs gap:${gap}µs thr:${thr}µs\n')

	mut out :=[]u8{}
	mut bit_idx := 0

	for i in 0 .. nbytes {
		mut ch := u8(0)
		mut ts_arr :=[]i64{}
		
		for _ in 0 .. 8 {
			time.sleep(10 * time.millisecond)
			t1 := resolve_safe('${bit_idx}.${base}')
			t2 := resolve_safe('v${bit_idx}.${base}')
			t3 := resolve_safe('w${bit_idx}.${base}')

			mut t := t1
			if t2 >= 0 && (t < 0 || t2 < t) { t = t2 }
			if t3 >= 0 && (t < 0 || t3 < t) { t = t3 }
			if t < 0 { die('bit ${bit_idx} failed') }

			ts_arr << t
			ch = (ch << 1) | (if t <= thr { u8(0) } else { u8(1) })
			bit_idx++
		}

		out << ch
		if ch.hex() == "ff" {
			bit_idx += nbytes
			unsafe { i = 0 }
		}
		println('  byte #${i}  ${ts_arr}µs  ->  0x${ch.hex()}')
	}

	decoded := huffman_decode(out)
	println('\n[rx] "${decoded}"')
}

fn main() {
	mut args :=[]string{}
	mut i := 1
	for i < os.args.len {
		if os.args[i] == '--dns' && i + 1 < os.args.len {
			g_dns = os.args[i + 1]
			i += 2
		} else if os.args[i] == '--workers' && i + 1 < os.args.len {
			g_workers = os.args[i + 1].int()
			if g_workers < 1 { g_workers = 1 }
			i += 2
		} else {
			args << os.args[i]
			i += 1
		}
	}

	if g_dns.len > 0 { println('[*] dns server: ${g_dns}') }

	if args.len < 1 {
		eprintln('dnsh [--dns SERVER] [--workers N] <send|rec> [domain] [msg|bytes]')
		eprintln('  sudo ./dnsh --dns 8.8.8.8 send x.com "hello world"')
		eprintln('  sudo ./dnsh --dns 8.8.8.8 rec  x.com 7')
		exit(1)
	}
	match args[0] {
		'send' {
			d := if args.len > 1 { args[1] } else { 'x.com' }
			m := if args.len > 2 { args[2] } else { 'hi' }
			send_mode(d, m)
		}
		'rec' {
			d := if args.len > 1 { args[1] } else { 'x.com' }
			n := if args.len > 2 { args[2].int() } else { 3 }
			rec_mode(d, n)
		}
		else { die('send or rec') }
	}
}